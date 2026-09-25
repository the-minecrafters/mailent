use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use mailent_correlation::{FindingCorrelator, PostureInput, build_guidance, compute_posture};
use mailent_domain::{
    AssessmentRecord, CaptureMetadata, EmailProtocol, EmailSession, Finding, FindingSeverity,
    PostureGrade, PostureSubjectKind, ProtocolEvidence, RiskLevel, StartTlsState,
};
use mailent_policy::PolicyPack;
use mailent_reporting::{ReportInput, build_report};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{credentials, installation};

pub struct AnalysisOptions<'a> {
    pub capture_path: &'a Path,
    pub capture_name: Option<String>,
    pub title: Option<String>,
    pub zeek_override: Option<&'a Path>,
    pub verify_checksums: bool,
    pub no_reports: bool,
    pub output_dir: Option<&'a Path>,
    pub sync: bool,
    pub server_override: Option<String>,
}

pub struct AnalysisOutcome {
    pub assessment: AssessmentRecord,
    pub findings: Vec<Finding>,
    pub assets: Vec<mailent_domain::Asset>,
    pub sessions: Vec<EmailSession>,
    pub posture_score: f32,
    pub posture_grade: String,
    pub ai_risk_classification: String,
    pub ai_risk_rationale: String,
    pub written_reports: Vec<PathBuf>,
    pub report: mailent_reporting::ForensicReport,
    pub file_size: u64,
    pub capture_hash: String,
    pub zeek_version: String,
    pub warnings: Vec<String>,
    pub synced: bool,
}

pub fn validate_pcap(path: &Path) -> Result<(u64, String), String> {
    if !path.exists() {
        return Err(format!("Capture file does not exist: {}", path.display()));
    }
    let metadata =
        std::fs::metadata(path).map_err(|e| format!("Failed to inspect capture file: {e}"))?;
    let len = metadata.len();
    if len < 24 {
        return Err(format!(
            "File '{}' is too small to be a valid PCAP/PCAPNG capture ({} bytes)",
            path.display(),
            len
        ));
    }
    if len > 256 * 1024 * 1024 {
        return Err(format!(
            "Capture file '{}' exceeds maximum allowed size of 256 MiB",
            path.display()
        ));
    }

    let mut file =
        std::fs::File::open(path).map_err(|e| format!("Failed to open capture file: {e}"))?;
    let mut header = [0u8; 4];
    std::io::Read::read_exact(&mut file, &mut header)
        .map_err(|e| format!("Failed to read capture header: {e}"))?;

    let valid_magic = matches!(
        header,
        [0xd4, 0xc3, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0xc3, 0xd4]
            | [0x4d, 0x3c, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0x3c, 0x4d]
            | [0x0a, 0x0d, 0x0d, 0x0a]
    );

    if !valid_magic {
        return Err(format!(
            "File '{}' is not a valid PCAP or PCAPNG packet capture (invalid magic header: {:02x?})",
            path.display(),
            header
        ));
    }

    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path)
        .map_err(|e| format!("Failed to read capture file for hashing: {e}"))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).map_err(|e| format!("Failed to hash capture: {e}"))?;
    let hash = format!("{:x}", hasher.finalize());

    Ok((len, hash))
}

pub fn verified_zeek_version(path: &Path) -> Result<String, String> {
    let is_script = cfg!(windows)
        && path
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("cmd") || e.eq_ignore_ascii_case("bat"));

    let mut cmd = if is_script {
        let mut c = std::process::Command::new("cmd.exe");
        c.arg("/c").arg(path);
        c
    } else {
        std::process::Command::new(path)
    };

    let output = cmd
        .arg("--version")
        .output()
        .map_err(|e| format!("Cannot start required Zeek at {}: {e}", path.display()))?;
    if !output.status.success() {
        return Err(format!(
            "Zeek is not ready at {}. Run the installer again or set MAILENT_ZEEK to Zeek 8+.",
            path.display()
        ));
    }
    let version = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let normalized = version
        .split_whitespace()
        .find(|part| {
            part.split('.')
                .next()
                .is_some_and(|v| v.parse::<u32>().is_ok())
        })
        .unwrap_or("");
    let major = version
        .split_whitespace()
        .find_map(|part| part.split('.').next()?.parse::<u32>().ok());
    if !major.is_some_and(|v| v >= 8) {
        return Err(format!(
            "Mailent requires Zeek 8 or newer; found {}",
            version.trim()
        ));
    }
    Ok(normalized.to_string())
}

pub fn locate_zeek(user_path: Option<&Path>) -> Result<PathBuf, String> {
    fn verified(path: PathBuf) -> Result<PathBuf, String> {
        verified_zeek_version(&path)?;
        Ok(if path.is_relative() && path.components().count() > 1 {
            std::fs::canonicalize(&path).unwrap_or(path)
        } else {
            path
        })
    }
    if let Some(path) = user_path {
        return verified(path.to_path_buf());
    }
    if let Some(path) = std::env::var_os("MAILENT_ZEEK") {
        return verified(PathBuf::from(path));
    }
    if let Ok(path) = verified(PathBuf::from("zeek")) {
        return Ok(path);
    }
    #[cfg(windows)]
    if let Ok(path) = verified(PathBuf::from("zeek.exe")) {
        return Ok(path);
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent() {
            for name in [
                "mailent-zeek",
                "mailent-zeek.cmd",
                "mailent-zeek.bat",
                "zeek.exe",
            ] {
                let adjacent = dir.join(name);
                if adjacent.exists()
                    && let Ok(verified_path) = verified(adjacent) {
                        return Ok(verified_path);
                    }
            }
        }
    for candidate in [
        "scripts/mailent-zeek",
        "scripts/mailent-zeek.cmd",
        "../scripts/mailent-zeek",
        "../scripts/mailent-zeek.cmd",
        "../../scripts/mailent-zeek",
        "../../scripts/mailent-zeek.cmd",
    ] {
        let p = PathBuf::from(candidate);
        if p.exists()
            && let Ok(verified_path) = verified(p) {
                return Ok(verified_path);
            }
    }
    Err("Zeek 8+ is required for Mailent. Run the website installer to set up Zeek, or set MAILENT_ZEEK to your Zeek executable.".into())
}

pub async fn sync_assessment(
    server_override: Option<String>,
    assessment: &AssessmentRecord,
    findings: &[Finding],
    assets: &[mailent_domain::Asset],
    sessions: &[EmailSession],
    zeek: Option<&Path>,
) -> Result<(), String> {
    let creds = credentials::load_credentials().ok_or_else(|| {
        "Not logged in. Run `mailent login` to register this device before using --sync."
            .to_string()
    })?;

    let server_url = server_override
        .or_else(|| std::env::var("MAILENT_SERVER_URL").ok())
        .unwrap_or(creds.server_url.clone());

    let client = reqwest::Client::new();
    let url = format!(
        "{}/api/v1/assessments/sync",
        server_url.trim_end_matches('/')
    );

    let payload = serde_json::json!({
        "client_sync_id": assessment.id.to_string(),
        "assessment": assessment,
        "findings": findings,
        "assets": assets,
        "sessions": sessions,
    });

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", creds.device_token))
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Failed to connect to Mailent server at {url}: {e}"))?;

    if credentials::handle_rejection(resp.status(), &creds)? {
        return Err("Sign in again before syncing results.".into());
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Sync failed (HTTP {status}): {body}"));
    }

    installation::report_best_effort(&creds, &server_url, zeek).await;
    println!(
        "\x1b[32m✔ Successfully synced assessment {} to {}\x1b[0m",
        assessment.id, server_url
    );
    Ok(())
}

pub async fn execute_capture_analysis(opts: AnalysisOptions<'_>) -> Result<AnalysisOutcome, String> {
    let capture_path = opts.capture_path;
    let capture_name = opts.capture_name.unwrap_or_else(|| {
        capture_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("capture.pcap")
            .to_string()
    });

    let (file_size, capture_hash) = validate_pcap(capture_path)?;
    let zeek_bin = locate_zeek(opts.zeek_override)?;

    let analysis = mailent_sensor::analyze::analyze(
        capture_path,
        &zeek_bin,
        "mailent-cli",
        !opts.verify_checksums,
    )
    .await
    .map_err(|e| format!("Capture analysis failed: {e}"))?;

    if analysis.observations.is_empty() {
        return Err(
            "No email connections were found in this capture. Choose traffic containing SMTP, IMAP or POP3.".to_string(),
        );
    }

    let policy_pack = PolicyPack::modern();
    let mut sessions = Vec::new();
    let mut all_findings: Vec<Finding> = Vec::new();
    let mut protocols_set = BTreeSet::new();
    let mut protocol_evidence = Vec::new();
    let now = OffsetDateTime::now_utc();

    for obs in &analysis.observations {
        let proto_name = match obs.protocol {
            EmailProtocol::Smtp => {
                if obs.starttls_state == Some(StartTlsState::AdvertisedAndUsed)
                    || obs.starttls_state == Some(StartTlsState::TlsEstablished)
                {
                    "SMTP (STARTTLS)"
                } else if obs.flow.dst_port == 465 {
                    "SMTPS"
                } else {
                    "SMTP"
                }
            }
            EmailProtocol::Imap => {
                if obs.starttls_state == Some(StartTlsState::AdvertisedAndUsed)
                    || obs.starttls_state == Some(StartTlsState::TlsEstablished)
                {
                    "IMAP (STARTTLS)"
                } else if obs.flow.dst_port == 993 {
                    "IMAPS"
                } else {
                    "IMAP"
                }
            }
            EmailProtocol::Pop3 => {
                if obs.starttls_state == Some(StartTlsState::AdvertisedAndUsed)
                    || obs.starttls_state == Some(StartTlsState::TlsEstablished)
                {
                    "POP3 (STLS)"
                } else if obs.flow.dst_port == 995 {
                    "POP3S"
                } else {
                    "POP3"
                }
            }
            EmailProtocol::Unknown => {
                if obs.flow.dst_port == 465 {
                    "SMTPS"
                } else if obs.flow.dst_port == 993 {
                    "IMAPS"
                } else if obs.flow.dst_port == 995 {
                    "POP3S"
                } else {
                    "Unknown Email Protocol"
                }
            }
        };

        if protocols_set.insert(proto_name.to_string()) {
            let clean_ver = analysis
                .zeek_version
                .trim_start_matches("zeek ")
                .trim_start_matches("Zeek ")
                .trim_start_matches("version ")
                .trim();
            let proto_lower = proto_name.to_lowercase();
            let verified_by = if clean_ver.is_empty() {
                format!("Zeek {proto_lower} analyzer")
            } else {
                format!("Zeek {clean_ver} · {proto_lower} analyzer")
            };
            protocol_evidence.push(ProtocolEvidence {
                protocol: proto_name.to_string(),
                role: if obs.flow.dst_port == 25
                    || obs.flow.dst_port == 465
                    || obs.flow.dst_port == 587
                {
                    "Mail Transfer Agent / Submission Server".to_string()
                } else {
                    "Mailbox Access Server".to_string()
                },
                proof: format!(
                    "Observed on flow {} with protocol handshake state machine",
                    obs.flow
                ),
                verified_by,
            });
        }

        let session = EmailSession::from(obs);
        let candidates = mailent_policy::evaluate(&session, &policy_pack);
        let correlated = FindingCorrelator::correlate_session(&session, &candidates);
        all_findings.extend(correlated);
        sessions.push(session);
    }

    let mut deduped_findings: Vec<Finding> = Vec::new();
    for finding in all_findings {
        if let Some(existing) = deduped_findings
            .iter_mut()
            .find(|f| f.rule_id == finding.rule_id && f.title == finding.title)
        {
            existing.affected_count += finding.affected_count;
            for ev in finding.evidence {
                if !existing.evidence.iter().any(|e| e == &ev) {
                    existing.evidence.push(ev);
                }
            }
            if finding.last_seen > existing.last_seen {
                existing.last_seen = finding.last_seen;
            }
            if finding.first_seen < existing.first_seen {
                existing.first_seen = finding.first_seen;
            }
        } else {
            deduped_findings.push(finding);
        }
    }
    let all_findings = deduped_findings;

    let asset_id = Uuid::new_v5(&Uuid::NAMESPACE_OID, capture_hash.as_bytes());
    let posture_input = PostureInput {
        findings: &all_findings,
        anomalies: &[],
        asset: None,
        asset_sessions: &sessions,
        certificates: &[],
        probe_runs: &[],
        investigation: None,
    };
    let posture = compute_posture(PostureSubjectKind::Asset, asset_id, &posture_input);
    let guidance = build_guidance(asset_id, &all_findings, None, &sessions, &[], now);

    let posture_score = posture.score;
    let posture_grade = posture.grade.to_string();

    let baseline_risk = match posture.grade {
        PostureGrade::Strong | PostureGrade::Good => RiskLevel::Low,
        PostureGrade::Moderate => RiskLevel::Medium,
        PostureGrade::Weak => RiskLevel::High,
        PostureGrade::Critical => RiskLevel::Critical,
    };

    let max_finding_risk = all_findings
        .iter()
        .map(|f| RiskLevel::from(f.severity))
        .max()
        .unwrap_or(RiskLevel::Low);

    let effective_risk = baseline_risk.max(max_finding_risk);

    let ai_risk_classification = match effective_risk {
        RiskLevel::Critical => "CRITICAL".to_string(),
        RiskLevel::High => "HIGH".to_string(),
        RiskLevel::Medium => "MEDIUM".to_string(),
        RiskLevel::Low => {
            if sessions.is_empty() {
                "INCONCLUSIVE".to_string()
            } else {
                "LOW".to_string()
            }
        }
    };

    let ai_risk_rationale = if all_findings
        .iter()
        .any(|f| f.severity == FindingSeverity::Critical)
    {
        "Critical cryptographic non-compliances detected that expose email transport to active downgrade or interception."
            .to_string()
    } else if all_findings
        .iter()
        .any(|f| f.severity == FindingSeverity::High)
    {
        "High severity security non-compliance identified; prompt remediation recommended to maintain transport security."
            .to_string()
    } else if all_findings.is_empty() {
        "Evaluated email transport complies with modern cryptographic baseline; no policy violations observed."
            .to_string()
    } else {
        "Moderate security observations detected; review recommendations to align with modern cryptographic best practices."
            .to_string()
    };

    let time_range_start = analysis.observations.iter().map(|o| o.timestamp).min();
    let time_range_end = analysis.observations.iter().map(|o| o.timestamp).max();

    let capture_meta = CaptureMetadata {
        capture_name: capture_name.clone(),
        capture_hash: capture_hash.clone(),
        capture_size_bytes: file_size,
        time_range_start,
        time_range_end,
    };

    let assessment_id = Uuid::new_v4();
    let session_ids = sessions.iter().map(|s| s.session_id).collect();
    let finding_ids = all_findings.iter().map(|f| f.id).collect();

    let assessment_title = opts
        .title
        .filter(|t| !t.trim().is_empty())
        .unwrap_or_else(|| format!("Capture Analysis: {}", capture_name));

    let assessment = AssessmentRecord::new_capture(
        assessment_id,
        assessment_title,
        capture_meta,
        now,
        protocols_set.into_iter().collect(),
        protocol_evidence,
        session_ids,
        vec![asset_id],
        finding_ids,
        posture_score,
        posture_grade.clone(),
        analysis.warnings.clone(),
        ai_risk_classification.clone(),
        ai_risk_rationale.clone(),
        0.0,
        serde_json::json!({
            "engine": "mailent-sensor",
            "zeek_version": analysis.zeek_version,
            "capture_sha256": capture_hash,
            "observations_count": analysis.observations.len(),
        }),
    );

    let report_input = ReportInput {
        investigation: None,
        asset: None,
        sessions: &sessions,
        findings: &all_findings,
        anomalies: &[],
        drifts: &[],
        probe_runs: &[],
        posture: Some(&posture),
        guidance: &guidance,
        remediation_records: &[],
        policy_name: policy_pack.name.clone(),
        policy_version: policy_pack.version.clone(),
        assessment_source: Some("capture".to_string()),
        target_domain: None,
        infrastructure: None,
    };

    let report = build_report(
        format!("Security report: {}", capture_name),
        "0.1.0",
        &report_input,
        now,
    );

    let mut written_reports = Vec::new();
    if !opts.no_reports
        && let Some(dir) = opts.output_dir {
            std::fs::create_dir_all(dir).map_err(|e| {
                format!("Failed to create output directory {}: {e}", dir.display())
            })?;

            let stem = capture_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("capture");

            let json_path = dir.join(format!("{stem}-report.json"));
            let json_content = mailent_reporting::to_json(&report)
                .map_err(|e| format!("Failed to render report JSON: {e}"))?;
            std::fs::write(&json_path, json_content)
                .map_err(|e| format!("Failed to write {}: {e}", json_path.display()))?;
            written_reports.push(json_path);

            let html_path = dir.join(format!("{stem}-report.html"));
            let html_content = mailent_reporting::render_html(&report)
                .map_err(|e| format!("Failed to render report HTML: {e}"))?;
            std::fs::write(&html_path, html_content)
                .map_err(|e| format!("Failed to write {}: {e}", html_path.display()))?;
            written_reports.push(html_path);

            let pdf_path = dir.join(format!("{stem}-report.pdf"));
            let pdf_bytes = mailent_reporting::render_pdf(&report)
                .map_err(|e| format!("Failed to render report PDF: {e}"))?;
            std::fs::write(&pdf_path, pdf_bytes)
                .map_err(|e| format!("Failed to write {}: {e}", pdf_path.display()))?;
            written_reports.push(pdf_path);
        }

    let mut synced = false;
    if opts.sync {
        sync_assessment(
            opts.server_override,
            &assessment,
            &all_findings,
            &[],
            &sessions,
            Some(&zeek_bin),
        )
        .await?;
        synced = true;
    }

    Ok(AnalysisOutcome {
        assessment,
        findings: all_findings,
        assets: vec![],
        sessions,
        posture_score,
        posture_grade,
        ai_risk_classification,
        ai_risk_rationale,
        written_reports,
        report,
        file_size,
        capture_hash,
        zeek_version: analysis.zeek_version,
        warnings: analysis.warnings,
        synced,
    })
}
