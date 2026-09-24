#![allow(clippy::collapsible_if, clippy::too_many_arguments)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use mailent_correlation::{FindingCorrelator, PostureInput, build_guidance, compute_posture};
use mailent_domain::{
    AssessmentRecord, CaptureMetadata, EmailProtocol, EmailSession, Finding, FindingSeverity,
    PostureGrade, PostureSubjectKind, ProtocolEvidence, RiskLevel, StartTlsState,
};
use mailent_integrations::LiveDomainIntelligenceResolver;
use mailent_policy::PolicyPack;
use mailent_probe::ProbeLimits;
use mailent_reporting::builder::{ReportInput, build_report};
use mailent_scanner::{DomainScanner, DomainScannerConfig};
use time::OffsetDateTime;
use uuid::Uuid;

mod agent;
mod credentials;
mod doctor;
mod monitor;

#[derive(Parser)]
#[command(
    name = "mailent",
    version,
    about = "Mailent — Email security from your terminal\nAnalyze local captures or check mail domains."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Register and authorize this device with a Mailent workspace
    Login {
        /// Mailent server URL (default: http://localhost:8080)
        #[arg(long)]
        server: Option<String>,

        /// Friendly name for this device
        #[arg(long)]
        name: Option<String>,
    },

    /// Check authentication status and active organization
    Status {
        /// Mailent server URL
        #[arg(long)]
        server: Option<String>,
    },

    /// Log out and revoke active device credentials
    Logout {
        /// Mailent server URL
        #[arg(long)]
        server: Option<String>,
    },

    /// Analyze a local PCAP or PCAPNG capture file
    Analyze {
        /// Path to the PCAP or PCAPNG capture file
        capture: PathBuf,

        /// Output format: table (default) or json
        #[arg(short, long, default_value = "table", value_parser = ["table", "json"])]
        format: String,

        /// Directory to write generated reports into (default: current directory)
        #[arg(short, long, default_value = ".")]
        output_dir: PathBuf,

        /// Path to Zeek executable (or zeek container runner)
        #[arg(long)]
        zeek: Option<PathBuf>,

        /// Enable packet checksum verification (disabled by default for offloaded captures)
        #[arg(long, default_value_t = false)]
        verify_checksums: bool,

        /// Skip writing report files to disk
        #[arg(long, default_value_t = false)]
        no_reports: bool,

        /// Sync assessment to Mailent organization workspace
        #[arg(long, default_value_t = false)]
        sync: bool,

        /// Mailent server URL
        #[arg(long)]
        server: Option<String>,
    },

    /// Check mail servers, encryption, certificates, and DNS settings
    Scan {
        /// Target domain to scan (e.g. example.com)
        domain: String,

        /// Output format: table (default) or json
        #[arg(short, long, default_value = "table", value_parser = ["table", "json"])]
        format: String,

        /// Directory to write generated reports into (default: current directory)
        #[arg(short, long, default_value = ".")]
        output_dir: PathBuf,

        /// Connection timeout per endpoint in seconds
        #[arg(long, default_value_t = 5)]
        timeout: u64,

        /// Skip writing report files to disk
        #[arg(long, default_value_t = false)]
        no_reports: bool,

        /// Sync assessment to Mailent organization workspace
        #[arg(long, default_value_t = false)]
        sync: bool,

        /// Mailent server URL
        #[arg(long)]
        server: Option<String>,
    },

    /// Monitor live mail traffic with Zeek and send results to your workspace
    Monitor {
        /// Network interface that sees your mail-server traffic
        #[arg(short, long)]
        interface: String,
        /// Path to the required Zeek executable
        #[arg(long)]
        zeek: Option<PathBuf>,
    },

    /// Manage scheduled mail-server checks
    #[command(subcommand)]
    Agent(agent::AgentCommands),

    /// Run system and connectivity diagnostics
    Doctor {
        /// Mailent server URL
        #[arg(long)]
        server: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Login { server, name } => run_login(server, name).await,
        Commands::Status { server } => run_status(server).await,
        Commands::Logout { server } => run_logout(server).await,
        Commands::Analyze {
            capture,
            format,
            output_dir,
            zeek,
            verify_checksums,
            no_reports,
            sync,
            server,
        } => {
            run_analyze(
                capture,
                format,
                output_dir,
                zeek,
                verify_checksums,
                no_reports,
                sync,
                server,
            )
            .await
        }
        Commands::Scan {
            domain,
            format,
            output_dir,
            timeout,
            no_reports,
            sync,
            server,
        } => {
            run_scan(
                domain, format, output_dir, timeout, no_reports, sync, server,
            )
            .await
        }
        Commands::Monitor { interface, zeek } => monitor::run(interface, zeek).await,
        Commands::Agent(agent_cmd) => agent::run_agent_command(agent_cmd).await,
        Commands::Doctor { server } => doctor::run_doctor(server).await,
    };

    if let Err(err) = result {
        eprintln!("Error: {err}");
        std::process::exit(1);
    }
}

async fn run_analyze(
    capture_path: PathBuf,
    format: String,
    output_dir: PathBuf,
    zeek_override: Option<PathBuf>,
    verify_checksums: bool,
    no_reports: bool,
    sync: bool,
    server_override: Option<String>,
) -> Result<(), String> {
    // 1. Validate capture file header and size
    let capture_name = capture_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("capture.pcap")
        .to_string();
    eprintln!("  [1/4] Validating capture file: {}", capture_name);
    let (file_size, capture_hash) = validate_pcap(&capture_path)?;

    // 2. Locate and verify Zeek
    let zeek_bin = locate_zeek(zeek_override.as_deref())?;

    // 3. Execute analysis library
    eprintln!(
        "  [2/4] Parsing network flows with Zeek engine ({})...",
        zeek_bin.display()
    );
    let analysis = mailent_sensor::analyze::analyze(
        &capture_path,
        &zeek_bin,
        "mailent-cli",
        !verify_checksums,
    )
    .await
    .map_err(|e| format!("Capture analysis failed: {e}"))?;

    // 4. Ingest and correlate observations
    if analysis.observations.is_empty() {
        return Err(
            "No email connections were found in this capture. Choose traffic containing SMTP, IMAP or POP3.".to_string(),
        );
    }

    eprintln!(
        "  [3/4] Correlating {} email observation(s) against policy baseline...",
        analysis.observations.len()
    );

    let policy_pack = PolicyPack::modern();
    let mut sessions = Vec::new();
    let mut all_findings: Vec<Finding> = Vec::new();
    let mut protocols_set = std::collections::BTreeSet::new();
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

    // 5. Compute Posture & Guidance
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

    eprintln!("  [4/4] Computing posture score and exporting security reports...");

    // 6. Build Assessment Record
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

    let assessment = AssessmentRecord::new_capture(
        assessment_id,
        format!("Capture Analysis: {}", capture_name),
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

    // 7. Build Canonical Forensic Report
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

    // 8. Generate Report Files
    let mut written_reports = Vec::new();
    if !no_reports {
        std::fs::create_dir_all(&output_dir).map_err(|e| {
            format!(
                "Failed to create output directory {}: {e}",
                output_dir.display()
            )
        })?;

        let stem = capture_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("capture");

        let json_path = output_dir.join(format!("{stem}-report.json"));
        let json_content = mailent_reporting::to_json(&report)
            .map_err(|e| format!("Failed to render report JSON: {e}"))?;
        std::fs::write(&json_path, json_content)
            .map_err(|e| format!("Failed to write {}: {e}", json_path.display()))?;
        written_reports.push(json_path);

        let html_path = output_dir.join(format!("{stem}-report.html"));
        let html_content = mailent_reporting::render_html(&report)
            .map_err(|e| format!("Failed to render report HTML: {e}"))?;
        std::fs::write(&html_path, html_content)
            .map_err(|e| format!("Failed to write {}: {e}", html_path.display()))?;
        written_reports.push(html_path);

        let pdf_path = output_dir.join(format!("{stem}-report.pdf"));
        let pdf_bytes = mailent_reporting::render_pdf(&report)
            .map_err(|e| format!("Failed to render report PDF: {e}"))?;
        std::fs::write(&pdf_path, pdf_bytes)
            .map_err(|e| format!("Failed to write {}: {e}", pdf_path.display()))?;
        written_reports.push(pdf_path);
    }

    eprintln!("  ✔ Analysis complete.\n");

    // 9. Output formatted result
    if format == "json" {
        let output = serde_json::json!({
            "assessment": assessment,
            "report_summary": {
                "report_id": report.metadata.report_id,
                "title": report.metadata.title,
                "posture_score": posture_score,
                "posture_grade": posture_grade,
                "risk_level": ai_risk_classification,
                "sessions_count": sessions.len(),
                "findings_count": all_findings.len(),
            },
            "written_reports": written_reports.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        print_capture_table(
            &capture_name,
            &capture_hash,
            file_size,
            &analysis.zeek_version,
            posture_score,
            &posture_grade,
            &ai_risk_classification,
            &ai_risk_rationale,
            &sessions,
            &all_findings,
            &written_reports,
            &analysis.warnings,
        );
    }

    if sync {
        sync_assessment(server_override, &assessment, &all_findings, &[], &sessions).await?;
    }

    Ok(())
}

async fn run_scan(
    raw_domain: String,
    format: String,
    output_dir: PathBuf,
    timeout_secs: u64,
    no_reports: bool,
    sync: bool,
    server_override: Option<String>,
) -> Result<(), String> {
    // Validate input before checking installed dependencies.
    let domain = mailent_scanner::normalize_scan_domain(&raw_domain).map_err(|e| e.to_string())?;
    locate_zeek(None)?;

    // 2. Initialize live scanner engine
    let resolver = LiveDomainIntelligenceResolver::new()
        .map_err(|e| format!("Failed to initialize live resolver: {e}"))?;

    let config = DomainScannerConfig {
        probe_limits: ProbeLimits {
            connect_timeout: Duration::from_secs(timeout_secs),
            read_timeout: Duration::from_secs(timeout_secs * 2),
            ..Default::default()
        },
        policy_pack: PolicyPack::modern(),
        sensor_hostname: "mailent-cli".to_string(),
        ..Default::default()
    };

    let scanner = DomainScanner::new(Arc::new(resolver), config);

    // 3. Execute domain scan
    let scan_result = scanner
        .scan_domain_with_progress(&domain, |event| match event {
            mailent_scanner::ScanProgressEvent::DiscoveringDns { domain } => {
                eprintln!("  [1/4] Discovering DNS records & mail servers for {domain}...");
            }
            mailent_scanner::ScanProgressEvent::DnsDiscovered { endpoints_count } => {
                eprintln!("        Discovered {endpoints_count} mail endpoint(s)");
            }
            mailent_scanner::ScanProgressEvent::FetchingPolicies => {
                eprintln!("  [2/4] Fetching MTA-STS and TLS-RPT policies...");
            }
            mailent_scanner::ScanProgressEvent::ProbingEndpoint {
                current,
                total,
                endpoint,
                service,
            } => {
                eprintln!(
                    "  [3/4] Probing endpoint [{current}/{total}] ({service} {endpoint})..."
                );
            }
            mailent_scanner::ScanProgressEvent::AnalyzingPosture => {
                eprintln!("  [4/4] Computing cryptographic posture and generating reports...");
            }
            mailent_scanner::ScanProgressEvent::Complete => {
                eprintln!("  ✔ Scan completed successfully.\n");
            }
        })
        .await
        .map_err(|e| format!("Domain infrastructure scan failed: {e}"))?;

    // 4. Generate Report Files
    let mut written_reports = Vec::new();
    if !no_reports {
        std::fs::create_dir_all(&output_dir).map_err(|e| {
            format!(
                "Failed to create output directory {}: {e}",
                output_dir.display()
            )
        })?;

        let json_path = output_dir.join(format!("{domain}-report.json"));
        let json_content = mailent_reporting::to_json(&scan_result.report)
            .map_err(|e| format!("Failed to render report JSON: {e}"))?;
        std::fs::write(&json_path, json_content)
            .map_err(|e| format!("Failed to write {}: {e}", json_path.display()))?;
        written_reports.push(json_path);

        let html_path = output_dir.join(format!("{domain}-report.html"));
        let html_content = mailent_reporting::render_html(&scan_result.report)
            .map_err(|e| format!("Failed to render report HTML: {e}"))?;
        std::fs::write(&html_path, html_content)
            .map_err(|e| format!("Failed to write {}: {e}", html_path.display()))?;
        written_reports.push(html_path);

        let pdf_path = output_dir.join(format!("{domain}-report.pdf"));
        let pdf_bytes = mailent_reporting::render_pdf(&scan_result.report)
            .map_err(|e| format!("Failed to render report PDF: {e}"))?;
        std::fs::write(&pdf_path, pdf_bytes)
            .map_err(|e| format!("Failed to write {}: {e}", pdf_path.display()))?;
        written_reports.push(pdf_path);
    }

    // 5. Output formatted result
    if format == "json" {
        let output = serde_json::json!({
            "assessment": scan_result.assessment,
            "endpoints_checked": scan_result.endpoints_checked,
            "endpoints_succeeded": scan_result.endpoints_succeeded,
            "endpoints_failed": scan_result.endpoints_failed,
            "written_reports": written_reports.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        print_scan_table(&scan_result, &written_reports);
    }

    if sync {
        sync_assessment(
            server_override,
            &scan_result.assessment,
            &scan_result.findings,
            &[],
            &scan_result.sessions,
        )
        .await?;
    }

    Ok(())
}

async fn sync_assessment(
    server_override: Option<String>,
    assessment: &AssessmentRecord,
    findings: &[Finding],
    assets: &[mailent_domain::Asset],
    sessions: &[EmailSession],
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

    println!(
        "\x1b[32m✔ Successfully synced assessment {} to {}\x1b[0m",
        assessment.id, server_url
    );
    Ok(())
}

async fn run_login(
    server_override: Option<String>,
    name_override: Option<String>,
) -> Result<(), String> {
    let server_url = server_override
        .or_else(|| std::env::var("MAILENT_SERVER_URL").ok())
        .unwrap_or_else(|| "http://localhost:8080".to_string());

    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "localhost".to_string());

    let device_name = name_override.unwrap_or_else(|| format!("Mailent CLI ({hostname})"));

    println!("Initiating device registration with {}", server_url);
    let client = reqwest::Client::new();
    let challenge_url = format!(
        "{}/api/v1/devices/authorize/challenge",
        server_url.trim_end_matches('/')
    );

    let challenge_req = serde_json::json!({
        "device_name": device_name,
        "hostname": hostname,
        "platform": std::env::consts::OS,
        "architecture": std::env::consts::ARCH,
    });

    let resp = client
        .post(&challenge_url)
        .json(&challenge_req)
        .send()
        .await
        .map_err(|e| format!("Failed to initiate authorization with {challenge_url}: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("Challenge request failed (HTTP {status}): {text}"));
    }

    let challenge_data: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse challenge response: {e}"))?;

    let code = challenge_data["code"]
        .as_str()
        .ok_or("Missing code in response")?;
    let verification_url = challenge_data["verification_url"]
        .as_str()
        .unwrap_or("/settings?tab=devices");
    let poll_interval = challenge_data["poll_interval_seconds"]
        .as_u64()
        .unwrap_or(2);

    let full_verify_url = if verification_url.starts_with("http") {
        verification_url.to_string()
    } else {
        format!("{}{}", server_url.trim_end_matches('/'), verification_url)
    };

    println!();
    println!("========================================================");
    println!("  Device Authorization Code: \x1b[1;36m{}\x1b[0m", code);
    println!(
        "  Approve in Mailent Web:    \x1b[4m{}\x1b[0m",
        full_verify_url
    );
    println!("========================================================");
    println!("Waiting for approval...");

    let poll_url = format!(
        "{}/api/v1/devices/authorize/poll",
        server_url.trim_end_matches('/')
    );
    let poll_req = serde_json::json!({ "code": code });

    let start_time = std::time::Instant::now();
    let timeout = Duration::from_secs(900); // 15 minutes

    loop {
        if start_time.elapsed() > timeout {
            return Err("Authorization timed out. Please run `mailent login` again.".to_string());
        }

        tokio::time::sleep(Duration::from_secs(poll_interval)).await;

        let poll_resp = client.post(&poll_url).json(&poll_req).send().await;

        let poll_resp = match poll_resp {
            Ok(r) => r,
            Err(_) => continue,
        };

        if poll_resp.status() == reqwest::StatusCode::ACCEPTED {
            continue;
        }

        if poll_resp.status().is_success() {
            let data: serde_json::Value = poll_resp
                .json()
                .await
                .map_err(|e| format!("Failed to parse poll response: {e}"))?;

            if data["status"] == "approved" {
                let token = data["token"]
                    .as_str()
                    .ok_or("Missing token in approved response")?;
                let device_id_str = data["device_id"].as_str().unwrap_or_default();
                let device_id = Uuid::parse_str(device_id_str).unwrap_or_else(|_| Uuid::new_v4());
                let org_id = data["organization_id"]
                    .as_str()
                    .and_then(|s| Uuid::parse_str(s).ok());

                let creds = credentials::DeviceCredentials {
                    server_url: server_url.clone(),
                    device_id,
                    device_token: token.to_string(),
                    organization_id: org_id,
                    device_name: device_name.clone(),
                    created_at: OffsetDateTime::now_utc()
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default(),
                };

                credentials::save_credentials(&creds)
                    .map_err(|e| format!("Failed to save credentials: {e}"))?;

                println!();
                println!("\x1b[32m✔ Device successfully authorized!\x1b[0m");
                println!("  Device Name:     {}", creds.device_name);
                println!("  Device ID:       {}", creds.device_id);
                if let Some(oid) = creds.organization_id {
                    println!("  Organization ID: {}", oid);
                }
                println!(
                    "  Credentials:     {}",
                    credentials::credentials_path().display()
                );
                return Ok(());
            }
        } else {
            let text = poll_resp.text().await.unwrap_or_default();
            return Err(format!("Authorization failed: {text}"));
        }
    }
}

async fn run_status(server_override: Option<String>) -> Result<(), String> {
    let creds = match credentials::load_credentials() {
        Some(c) => c,
        None => {
            println!("Status: Not authenticated");
            println!(
                "No credentials found at {}",
                credentials::credentials_path().display()
            );
            println!("Run `mailent login` to register this device.");
            return Ok(());
        }
    };

    let server_url = server_override
        .or_else(|| std::env::var("MAILENT_SERVER_URL").ok())
        .unwrap_or(creds.server_url.clone());

    let client = reqwest::Client::new();
    let url = format!("{}/api/v1/devices/status", server_url.trim_end_matches('/'));

    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", creds.device_token))
        .send()
        .await
        .map_err(|e| format!("Failed to connect to {url}: {e}"))?;

    if credentials::handle_rejection(resp.status(), &creds)? {
        println!("Status: Unauthorized / Token Revoked");
        println!(
            "Device credentials at {} are invalid or revoked.",
            credentials::credentials_path().display()
        );
        println!("Run `mailent login` to re-authorize this device.");
        return Ok(());
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Server returned HTTP {status}: {body}"));
    }

    let status_data: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse status response: {e}"))?;

    println!("Mailent CLI Status");
    println!("------------------");
    println!("Authentication:  \x1b[32mActive\x1b[0m");
    println!("Device Name:     {}", creds.device_name);
    println!("Device ID:       {}", creds.device_id);
    if let Some(org) = status_data.get("organization") {
        let org_name = org["name"].as_str().unwrap_or("Unknown");
        let org_id = org["id"].as_str().unwrap_or("Unknown");
        println!("Organization:    {} ({})", org_name, org_id);
    }
    println!("Server:          {}", server_url);
    println!(
        "Credentials:     {}",
        credentials::credentials_path().display()
    );

    Ok(())
}

async fn run_logout(server_override: Option<String>) -> Result<(), String> {
    let creds = match credentials::load_credentials() {
        Some(c) => c,
        None => {
            println!("Not logged in.");
            return Ok(());
        }
    };

    let server_url = server_override
        .or_else(|| std::env::var("MAILENT_SERVER_URL").ok())
        .unwrap_or(creds.server_url.clone());

    let client = reqwest::Client::new();
    let url = format!("{}/api/v1/devices/logout", server_url.trim_end_matches('/'));

    let _ = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", creds.device_token))
        .send()
        .await;

    credentials::clear_credentials()
        .map_err(|e| format!("Failed to remove credentials file: {e}"))?;

    println!("\x1b[32m✔ Logged out successfully. Local credentials removed.\x1b[0m");
    Ok(())
}

fn validate_pcap(path: &Path) -> Result<(u64, String), String> {
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

fn locate_zeek(user_path: Option<&Path>) -> Result<PathBuf, String> {
    fn verified(path: PathBuf) -> Result<PathBuf, String> {
        let is_script = cfg!(windows)
            && path
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("cmd") || e.eq_ignore_ascii_case("bat"));

        let mut cmd = if is_script {
            let mut c = std::process::Command::new("cmd.exe");
            c.arg("/c").arg(&path);
            c
        } else {
            std::process::Command::new(&path)
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
        let major = version
            .split_whitespace()
            .find_map(|part| part.split('.').next()?.parse::<u32>().ok());
        if !major.is_some_and(|v| v >= 8) {
            return Err(format!(
                "Mailent requires Zeek 8 or newer; found {}",
                version.trim()
            ));
        }
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
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for name in [
                "mailent-zeek",
                "mailent-zeek.cmd",
                "mailent-zeek.bat",
                "zeek.exe",
            ] {
                let adjacent = dir.join(name);
                if adjacent.exists() {
                    if let Ok(verified_path) = verified(adjacent) {
                        return Ok(verified_path);
                    }
                }
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
        if p.exists() {
            if let Ok(verified_path) = verified(p) {
                return Ok(verified_path);
            }
        }
    }
    Err("Zeek 8+ is required for Mailent. Run the website installer to set up Zeek, or set MAILENT_ZEEK to your Zeek executable.".into())
}

fn print_capture_table(
    capture_name: &str,
    capture_hash: &str,
    size_bytes: u64,
    zeek_version: &str,
    posture_score: f32,
    posture_grade: &str,
    risk_level: &str,
    risk_rationale: &str,
    sessions: &[EmailSession],
    findings: &[Finding],
    reports: &[PathBuf],
    warnings: &[String],
) {
    println!("\n╔════════════════════════════════════════════════════════════════════════════╗");
    println!("║                   MAILENT CAPTURE ANALYSIS                               ║");
    println!("╚════════════════════════════════════════════════════════════════════════════╝");
    println!("  Capture:       {}", capture_name);
    println!("  SHA-256:       {}", capture_hash);
    println!(
        "  Size:          {:.2} KiB ({} bytes)",
        size_bytes as f64 / 1024.0,
        size_bytes
    );
    println!("  Analyzer:      {}", zeek_version);
    println!();
    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!("│ SECURITY POSTURE & RISK VERDICT                                            │");
    println!("├────────────────────────────────────────────────────────────────────────────┤");
    println!("  Score:         {:.1} / 100", posture_score);
    println!("  Grade:         {}", posture_grade);
    println!("  Risk Level:    {}", risk_level);
    println!("  Verdict:       {}", risk_rationale);
    println!();
    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!(
        "│ RECONSTRUCTED EMAIL SESSIONS ({} found)                                    │",
        sessions.len()
    );
    println!("├────────────────────────────────────────────────────────────────────────────┤");
    if sessions.is_empty() {
        println!("  No email sessions identified in capture.");
    }
    for (i, s) in sessions.iter().enumerate() {
        println!(
            "  [{}] {:?} | {} -> {}",
            i + 1,
            s.protocol,
            s.flow.src_ip,
            s.flow.dst_ip
        );
        if let Some(st) = &s.starttls_state {
            println!("      STARTTLS:        {:?}", st);
        }
        if let Some(v) = &s.tls_version {
            println!("      TLS Version:     {}", v);
        }
        if let Some(c) = &s.cipher_suite {
            println!("      Cipher Suite:    {}", c.name);
        }
        if let Some(ke) = &s.key_exchange {
            println!("      Key Exchange:    {:?}", ke);
        }
        if let Some(cert) = &s.certificate {
            println!("      Certificate:     CN={}", cert.reference.subject);
            println!("      Issuer:          {}", cert.reference.issuer);
            println!(
                "      Validity:        {} -> {}",
                cert.validity.not_before, cert.validity.not_after
            );
        }
    }
    println!();
    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!(
        "│ POLICY & CRYPTOGRAPHIC FINDINGS ({} identified)                            │",
        findings.len()
    );
    println!("├────────────────────────────────────────────────────────────────────────────┤");
    if findings.is_empty() {
        println!("  No cryptographic or policy non-compliances detected.");
    }
    for f in findings {
        println!("  • [{}] {} (rule: {})", f.severity, f.title, f.rule_id);
        println!("    {}", f.description);
        println!("    Remediation: {}", f.remediation);
    }
    println!();
    if !warnings.is_empty() {
        println!("┌────────────────────────────────────────────────────────────────────────────┐");
        println!("│ EVIDENCE GAPS & WARNINGS                                                   │");
        println!("├────────────────────────────────────────────────────────────────────────────┤");
        for w in warnings {
            println!("  ! {}", w);
        }
        println!();
    }
    if !reports.is_empty() {
        println!("┌────────────────────────────────────────────────────────────────────────────┐");
        println!("│ EXPORTED SECURITY REPORTS                                                  │");
        println!("├────────────────────────────────────────────────────────────────────────────┤");
        for r in reports {
            println!("  -> {}", r.display());
        }
        println!();
    }
    println!("══════════════════════════════════════════════════════════════════════════════\n");
}

fn print_scan_table(result: &mailent_scanner::InfrastructureScanResult, reports: &[PathBuf]) {
    let report = &result.report;
    let infra = report.infrastructure.as_ref();

    println!("\n╔════════════════════════════════════════════════════════════════════════════╗");
    println!("║                MAILENT DOMAIN INFRASTRUCTURE ASSESSMENT                    ║");
    println!("╚════════════════════════════════════════════════════════════════════════════╝");
    println!(
        "  Domain:        {}",
        report
            .metadata
            .target_domain
            .as_deref()
            .unwrap_or("unknown")
    );
    println!(
        "  Endpoints:     {} checked ({} succeeded, {} failed/unreachable)",
        result.endpoints_checked, result.endpoints_succeeded, result.endpoints_failed
    );
    if let Some(inf) = infra {
        println!("  DNSSEC:        {}", inf.dnssec_status);
        println!(
            "  MTA-STS:       {}",
            inf.mta_sts_mode.as_deref().unwrap_or("Not published")
        );
        if let Some(details) = &inf.mta_sts_policy_details {
            println!("                 ({})", details);
        }
        println!(
            "  TLS-RPT:       {}",
            inf.tls_rpt_destination
                .as_deref()
                .unwrap_or("Not published")
        );
    }
    println!();
    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!("│ SECURITY POSTURE & RISK VERDICT                                            │");
    println!("├────────────────────────────────────────────────────────────────────────────┤");
    if let Some(p) = &report.posture {
        println!("  Score:         {:.1} / 100", p.score);
        println!("  Grade:         {}", p.grade);
    }
    println!(
        "  Risk Level:    {}",
        result.assessment.ai_risk_classification
    );
    println!("  Verdict:       {}", result.assessment.ai_risk_rationale);
    println!();
    if let Some(inf) = infra {
        println!("┌────────────────────────────────────────────────────────────────────────────┐");
        println!(
            "│ DISCOVERED ENDPOINTS & ACTIVE PROBE RESULTS ({} total)                      │",
            inf.discovered_endpoints.len()
        );
        println!("├────────────────────────────────────────────────────────────────────────────┤");
        for ep in &inf.discovered_endpoints {
            println!(
                "  [{}] {}:{} (priority: {})",
                ep.service,
                ep.host,
                ep.port,
                ep.priority
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "n/a".into())
            );
            if !ep.resolved_ips.is_empty() {
                println!("      IP Addresses:    {}", ep.resolved_ips.join(", "));
            }
            println!("      STARTTLS:        {}", ep.starttls_status);
            if let Some(tls) = &ep.tls_version {
                println!("      TLS Version:     {}", tls);
            }
            if let Some(c) = &ep.cipher {
                println!("      Cipher Suite:    {}", c);
            }
            if let Some(sub) = &ep.cert_subject {
                println!("      Certificate:     CN={}", sub);
            }
            if let Some(val) = &ep.cert_validity {
                println!("      Validity:        {}", val);
            }
            println!("      DANE Status:     {}", ep.dane_status);
        }
        println!();
    }
    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!(
        "│ POLICY & INFRASTRUCTURE FINDINGS ({} identified)                           │",
        report.findings.len()
    );
    println!("├────────────────────────────────────────────────────────────────────────────┤");
    if report.findings.is_empty() {
        println!("  No policy violations detected.");
    }
    for f in &report.findings {
        println!("  • [{}] {} (rule: {})", f.severity, f.title, f.rule_id);
        println!("    {}", f.description);
    }
    if !report.remediation.is_empty() {
        println!();
        println!("  Remediation Guidance:");
        for rem in &report.remediation {
            println!("  • {}", rem.title);
            println!("    {}", rem.recommendation);
        }
    }
    println!();
    if !report.evidence_gaps.is_empty() {
        println!("┌────────────────────────────────────────────────────────────────────────────┐");
        println!("│ COVERAGE GAPS & WARNINGS                                                   │");
        println!("├────────────────────────────────────────────────────────────────────────────┤");
        for g in &report.evidence_gaps {
            println!("  ! {}", g);
        }
        println!();
    }
    if !reports.is_empty() {
        println!("┌────────────────────────────────────────────────────────────────────────────┐");
        println!("│ EXPORTED SECURITY REPORTS                                                  │");
        println!("├────────────────────────────────────────────────────────────────────────────┤");
        for r in reports {
            println!("  -> {}", r.display());
        }
        println!();
    }
    println!("══════════════════════════════════════════════════════════════════════════════\n");
}
