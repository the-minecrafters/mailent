use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use mailent_domain::{
    AssessmentRecord, CaptureMetadata, EmailProtocol, ProtocolEvidence, StartTlsState,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use time::OffsetDateTime;
use tokio::process::Command;
use uuid::Uuid;

use crate::{auth::ExecutionContext, pipeline::process_observation, state::AppState};

#[derive(Debug, Deserialize)]
pub struct AnalyzeCaptureRequest {
    pub title: Option<String>,
    pub pcap_base64: Option<String>,
    pub file_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SensorAnalysisOutput {
    pub capture_sha256: String,
    #[serde(default)]
    pub zeek_version: String,
    pub observations: Vec<mailent_domain::NormalizedObservation>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

fn locate_sensor_binary() -> Result<PathBuf, String> {
    if let Ok(bin) = std::env::var("MAILENT_SENSOR_BIN") {
        let p = PathBuf::from(bin);
        if p.exists() {
            return Ok(p);
        }
    }
    for candidate in [
        "target/debug/mailent-sensor",
        "target/release/mailent-sensor",
        "../target/debug/mailent-sensor",
        "../../target/debug/mailent-sensor",
    ] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return Ok(p);
        }
    }
    // Check if in PATH
    if let Ok(output) = std::process::Command::new("which")
        .arg("mailent-sensor")
        .output()
        && output.status.success()
    {
        let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path_str.is_empty() {
            return Ok(PathBuf::from(path_str));
        }
    }
    Err("mailent-sensor binary not found. Build it with `cargo build -p mailent-sensor` or set MAILENT_SENSOR_BIN".to_string())
}

fn locate_zeek() -> PathBuf {
    if let Ok(z) = std::env::var("MAILENT_ZEEK") {
        let p = PathBuf::from(z);
        if p.exists() {
            return p;
        }
    }
    for candidate in [
        "scripts/mailent-zeek",
        "../scripts/mailent-zeek",
        "../../scripts/mailent-zeek",
        "scripts/zeek-container",
        "../scripts/zeek-container",
        "../../scripts/zeek-container",
    ] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return p;
        }
    }
    PathBuf::from("zeek")
}

pub async fn analyze_capture_handler(
    State(state): State<AppState>,
    ctx: Option<Extension<ExecutionContext>>,
    Json(req): Json<AnalyzeCaptureRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use base64::Engine;
    let b64 = req.pcap_base64.as_deref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "Choose a capture file to analyze.".to_string(),
        )
    })?;
    const MAX_CAPTURE_SIZE: usize = 50 * 1024 * 1024;
    if b64.len() > MAX_CAPTURE_SIZE.div_ceil(3) * 4 {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "Capture exceeds the 50 MB limit.".into(),
        ));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "The uploaded capture could not be decoded.".to_string(),
            )
        })?;
    if bytes.len() > MAX_CAPTURE_SIZE {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "Capture exceeds the 50 MB limit.".into(),
        ));
    }
    let valid_magic = bytes.get(..4).is_some_and(|magic| {
        matches!(
            magic,
            [0xd4, 0xc3, 0xb2, 0xa1]
                | [0xa1, 0xb2, 0xc3, 0xd4]
                | [0x4d, 0x3c, 0xb2, 0xa1]
                | [0xa1, 0xb2, 0x3c, 0x4d]
                | [0x0a, 0x0d, 0x0d, 0x0a]
        )
    });
    if !valid_magic || bytes.len() < 24 {
        return Err((
            StatusCode::BAD_REQUEST,
            "This file is not a valid PCAP or PCAPNG capture.".into(),
        ));
    }
    let mut temp_file = tempfile::Builder::new()
        .suffix(".pcap")
        .tempfile()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    use std::io::Write;
    temp_file
        .write_all(&bytes)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let pcap_path = temp_file.path().to_path_buf();
    let file_size = bytes.len() as u64;
    let capture_name = req
        .file_name
        .as_deref()
        .and_then(|name| std::path::Path::new(name).file_name())
        .and_then(|name| name.to_str())
        .unwrap_or("capture.pcap")
        .to_string();

    // Calculate SHA-256 of PCAP file
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let capture_hash = format!("{:x}", hasher.finalize());

    // Execute sensor analyze binary
    let sensor_bin = locate_sensor_binary().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let zeek_bin = locate_zeek();

    let output = tokio::time::timeout(
        std::time::Duration::from_secs(50),
        Command::new(&sensor_bin)
            .arg("analyze")
            .arg(&pcap_path)
            .arg("--zeek")
            .arg(&zeek_bin)
            .arg("--json")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| {
        (
            StatusCode::GATEWAY_TIMEOUT,
            "Analysis exceeded 50 seconds. Try a smaller capture.".to_string(),
        )
    })?
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to execute mailent-sensor: {e}"),
        )
    })?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        let lower = err.to_lowercase();
        if lower.contains("truncated dump")
            || lower.contains("failed to read a packet")
            || lower.contains("corrupt")
            || lower.contains("bad packet")
        {
            return Err((
                StatusCode::BAD_REQUEST,
                "The capture file is corrupted or truncated and could not be parsed.".to_string(),
            ));
        }
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Sensor analysis failed: {err}"),
        ));
    }

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    // Locate JSON starting with {
    let json_start = stdout_str.find('{').ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "No JSON output from mailent-sensor analyze".to_string(),
        )
    })?;
    let analysis: SensorAnalysisOutput =
        serde_json::from_str(&stdout_str[json_start..]).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to parse sensor JSON output: {e}"),
            )
        })?;

    if analysis.observations.is_empty() {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "No email connections were found in this capture. Choose traffic containing SMTP, IMAP or POP3.".into()));
    }
    let time_range_start = analysis.observations.iter().map(|obs| obs.timestamp).min();
    let time_range_end = analysis.observations.iter().map(|obs| obs.timestamp).max();
    let mut session_ids = Vec::new();
    let mut asset_ids = Vec::new();
    let mut finding_ids = Vec::new();
    let mut protocols_set = std::collections::HashSet::new();
    let mut protocol_evidence = Vec::new();
    let mut evidence_gaps = analysis.warnings.clone();
    let mut all_anomalies = Vec::new();
    let mut all_drifts = Vec::new();

    for obs in analysis.observations {
        let proto_name = match obs.protocol {
            EmailProtocol::Smtp => {
                if obs.starttls_state == Some(StartTlsState::TlsEstablished)
                    || obs.starttls_state == Some(StartTlsState::AdvertisedAndUsed)
                {
                    "SMTP (STARTTLS)"
                } else if obs.flow.dst_port == 465 {
                    "SMTPS"
                } else {
                    "SMTP"
                }
            }
            EmailProtocol::Imap => {
                if obs.starttls_state == Some(StartTlsState::TlsEstablished)
                    || obs.starttls_state == Some(StartTlsState::AdvertisedAndUsed)
                {
                    "IMAP (STARTTLS)"
                } else if obs.flow.dst_port == 993 {
                    "IMAPS"
                } else {
                    "IMAP"
                }
            }
            EmailProtocol::Pop3 => {
                if obs.starttls_state == Some(StartTlsState::TlsEstablished)
                    || obs.starttls_state == Some(StartTlsState::AdvertisedAndUsed)
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
            let role_desc = if obs.flow.dst_port == 25
                || obs.flow.dst_port == 465
                || obs.flow.dst_port == 587
            {
                "Mail delivery server"
            } else {
                "Mailbox server"
            };
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
                role: role_desc.to_string(),
                proof: format!(
                    "Recorded connection {}:{} → {}:{}",
                    obs.flow.src_ip, obs.flow.src_port, obs.flow.dst_ip, obs.flow.dst_port
                ),
                verified_by,
            });
        }

        if let Some(ref cap) = obs.capture {
            for g in &cap.gaps {
                if !evidence_gaps.contains(g) {
                    evidence_gaps.push(g.clone());
                }
            }
        }

        // Ingest observation into core pipeline
        let proc_res = process_observation(&state, obs)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        session_ids.push(proc_res.session_id);
        if !asset_ids.contains(&proc_res.asset_id) {
            asset_ids.push(proc_res.asset_id);
        }
        for f in proc_res.findings {
            if !finding_ids.contains(&f.id) {
                finding_ids.push(f.id);
            }
        }
        all_anomalies.extend(proc_res.anomalies);
        all_drifts.extend(proc_res.drift_events);
    }

    // Determine posture score and grade
    let mut total_score = 100.0f32;

    for f_id in &finding_ids {
        if let Ok(Some(f)) = state.findings.find_by_id(*f_id).await {
            match f.severity {
                mailent_domain::FindingSeverity::Critical => {
                    total_score -= 25.0;
                }
                mailent_domain::FindingSeverity::High => {
                    total_score -= 15.0;
                }
                mailent_domain::FindingSeverity::Medium => {
                    total_score -= 8.0;
                }
                mailent_domain::FindingSeverity::Low => {
                    total_score -= 3.0;
                }
            }
        }
    }
    if total_score < 0.0 {
        total_score = 0.0;
    }

    let grade = if total_score >= 90.0 {
        "A"
    } else if total_score >= 80.0 {
        "B"
    } else if total_score >= 70.0 {
        "C"
    } else if total_score >= 60.0 {
        "D"
    } else {
        "F"
    };

    let mut finding_candidates = Vec::new();
    let mut resolved_findings = Vec::new();
    for f_id in &finding_ids {
        if let Ok(Some(f)) = state.findings.find_by_id(*f_id).await {
            resolved_findings.push(f.clone());
            finding_candidates.push(mailent_domain::FindingCandidate {
                rule_id: f.rule_id.clone(),
                policy_name: f.policy_name.clone(),
                policy_version: f.policy_version.clone(),
                reference: f.reference.clone(),
                severity: f.severity,
                category: f.category,
                title: f.title.clone(),
                description: f.description.clone(),
                remediation: f.remediation.clone(),
                evidence: f.evidence.clone(),
            });
        }
    }

    let assessment_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();

    let decision_ctx = mailent_domain::DecisionContext {
        session_id: session_ids.first().copied().unwrap_or_else(Uuid::new_v4),
        findings: finding_candidates,
        metadata: serde_json::json!({
            "assessment_id": assessment_id,
            "capture_name": capture_name,
            "session_count": session_ids.len(),
            "asset_count": asset_ids.len(),
            "anomalies_count": all_anomalies.len(),
            "drifts_count": all_drifts.len(),
            "posture_score": total_score,
            "posture_grade": grade,
        }),
    };

    let (decision_result, provider_name) = if session_ids.is_empty() {
        (
            mailent_domain::DecisionResult {
                risk: mailent_domain::RiskLevel::Low,
                anomalous: false,
                human_review: false,
                priority: mailent_domain::PriorityLevel::Low,
                confidence: 0.0,
                provider_info: "empty".to_string(),
                reasons: vec!["No email connections were found in this capture to evaluate.".to_string()],
            },
            "none",
        )
    } else {
        match state.decision_provider.assess(decision_ctx.clone()).await {
            Ok(r) => {
                let p = if r.provider_info.starts_with("jev:") {
                    "jev"
                } else {
                    "jev-fallback"
                };
                (r, p)
            }
            Err(e) => {
                tracing::warn!("Jev assessment failed: {e}; applying deterministic fallback");
                (
                    mailent_decision::JevProvider::deterministic_fallback(&decision_ctx),
                    "jev-fallback",
                )
            }
        }
    };

    // Log decision record into audit store
    let decision_record = mailent_domain::DecisionRecord {
        id: Uuid::new_v4(),
        session_id: session_ids.first().copied(),
        asset_id: asset_ids.first().copied(),
        provider: provider_name.to_string(),
        model: decision_result.provider_info.clone(),
        decision: decision_result.clone(),
        latency_ms: 0,
        created_at: now,
    };
    let _ = state.decisions.save_record(&decision_record).await;

    let ai_risk_classification = match decision_result.risk {
        mailent_domain::RiskLevel::Critical => "CRITICAL".to_string(),
        mailent_domain::RiskLevel::High => "HIGH".to_string(),
        mailent_domain::RiskLevel::Medium => "MEDIUM".to_string(),
        mailent_domain::RiskLevel::Low => {
            if session_ids.is_empty() {
                "INCONCLUSIVE".to_string()
            } else {
                "LOW".to_string()
            }
        }
    };
    let ai_confidence = decision_result.confidence;
    let ai_risk_rationale = if decision_result.reasons.is_empty() {
        "No cryptographic policy violations were observed in the parsed email traffic.".to_string()
    } else {
        format!(
            "{} [Handling: {:?}, Human review: {}]",
            decision_result.reasons.join("; "),
            decision_result.priority,
            if decision_result.human_review { "recommended" } else { "not required" }
        )
    };

    // Synthesize Threat Prioritization Matrix and Actionable Remediation Roadmap
    let mut threat_matrix = Vec::new();
    let mut remediation_roadmap = Vec::new();

    for f in &resolved_findings {
        let (priority_tier, threat_vector, remediation_recipe) = match f.rule_id.as_str() {
            "TLS_LEGACY_VERSION" => (
                "P1 - Immediate",
                "Downgrade & Cipher Interception: Attackers capable of passive or active interception can force legacy SSLv3/TLS 1.0 negotiations to exploit protocol weaknesses (e.g. POODLE, BEAST).",
                serde_json::json!({
                    "service": "postfix",
                    "action": "Enforce minimum TLS 1.2 on outbound and inbound listeners",
                    "commands": [
                        "postconf -e 'smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'",
                        "postconf -e 'smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'",
                        "postconf -e 'smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'",
                        "postfix reload"
                    ],
                    "dovecot": [
                        "ssl_min_protocol = TLSv1.2"
                    ]
                })
            ),
            "NO_FORWARD_SECRECY" => (
                "P2 - High",
                "Retrospective Decryption (Harvest Now, Decrypt Later): Static RSA key exchange allows any adversary that records ciphertexts today to decrypt all past email contents if the server's private RSA key is compromised.",
                serde_json::json!({
                    "service": "postfix",
                    "action": "Require Ephemeral Diffie-Hellman (ECDHE/DHE) or TLS 1.3",
                    "commands": [
                        "postconf -e 'smtpd_tls_ciphers = high'",
                        "postconf -e 'smtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, DES, RC4, MD5, PSK, aECDH, EDH-DSS-DES-CBC3-SHA, EDH-RSA-DES-CBC3-SHA, KRB5-DES, CBC3-SHA'",
                        "postfix reload"
                    ],
                    "dovecot": [
                        "ssl_cipher_list = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
                    ]
                })
            ),
            "CERTIFICATE_EXPIRED" => (
                "P2 - High",
                "Trust Breakdown & Delivery Failure: Remote sending MTAs enforcing MTA-STS or DANE will refuse to route incoming messages, causing delivery bounced errors and exposing users to impersonation warnings.",
                serde_json::json!({
                    "service": "certbot",
                    "action": "Renew X.509 certificate immediately via ACME/Certbot",
                    "commands": [
                        "certbot renew --post-hook 'postfix reload && dovecot reload'",
                        "certbot certificates"
                    ],
                    "dovecot": []
                })
            ),
            "STARTTLS_MISSING" => (
                "P1 - Immediate",
                "Plaintext Eavesdropping: Authentication credentials (SASL PLAIN/LOGIN) and confidential email content transit untrusted intermediate networks completely unencrypted.",
                serde_json::json!({
                    "service": "postfix",
                    "action": "Enable STARTTLS on SMTP port 25 and 587",
                    "commands": [
                        "postconf -e 'smtpd_tls_security_level = may'",
                        "postconf -e 'smtpd_tls_auth_only = yes'",
                        "postfix reload"
                    ],
                    "dovecot": [
                        "ssl = yes",
                        "disable_plaintext_auth = yes"
                    ]
                })
            ),
            _ => (
                "P3 - Medium",
                "General Cryptographic Misconfiguration: Deviates from RFC 8461/BCP 195 compliance recommendations.",
                serde_json::json!({
                    "service": "general",
                    "action": f.remediation.clone(),
                    "commands": [],
                    "dovecot": []
                })
            ),
        };

        threat_matrix.push(serde_json::json!({
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity.to_string(),
            "priority_tier": priority_tier,
            "threat_vector": threat_vector,
            "reference": f.reference,
        }));

        remediation_roadmap.push(serde_json::json!({
            "rule_id": f.rule_id,
            "title": f.title,
            "priority": priority_tier,
            "recipe": remediation_recipe,
        }));
    }

    let title = req
        .title
        .filter(|title| !title.trim().is_empty())
        .map(|title| title.trim().chars().take(160).collect())
        .unwrap_or_else(|| capture_name.clone());

    let capture_metadata = CaptureMetadata {
        capture_name,
        capture_hash,
        capture_size_bytes: file_size,
        time_range_start,
        time_range_end,
    };

    let mut assessment = AssessmentRecord::new_capture(
        assessment_id,
        title,
        capture_metadata,
        now,
        protocols_set.into_iter().collect(),
        protocol_evidence,
        session_ids,
        asset_ids,
        finding_ids,
        total_score,
        grade.to_string(),
        evidence_gaps,
        ai_risk_classification,
        ai_risk_rationale,
        ai_confidence,
        serde_json::json!({
            "risk_method": "jev",
            "ai_provider": provider_name,
            "jev_model": decision_result.provider_info,
            "jev_priority": format!("{:?}", decision_result.priority),
            "jev_human_review": decision_result.human_review,
            "policy_name": state.policy_pack.name,
            "policy_version": state.policy_pack.version,
            "anomalies": all_anomalies.iter().map(|a| serde_json::json!({
                "signal": a.signal,
                "title": a.title,
                "current_value": a.current_value,
                "baseline_value": a.baseline_value,
                "deviation": a.deviation,
                "confidence": a.confidence,
                "evidence": a.evidence,
            })).collect::<Vec<_>>(),
            "threat_matrix": threat_matrix,
            "remediation_roadmap": remediation_roadmap,
        }),
    );

    if let Some(Extension(ref c)) = ctx {
        if let Some(org_id) = c.organization_id {
            assessment = assessment.with_organization(org_id);
        }
    }

    // Save assessment to persistent storage
    state
        .assessments
        .save(&assessment)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Drop tempfile if any
    drop(temp_file);

    Ok((StatusCode::CREATED, Json(assessment)))
}

#[derive(Debug, Deserialize)]
pub struct SyncAssessmentRequest {
    pub client_sync_id: Option<String>,
    pub assessment: AssessmentRecord,
    #[serde(default)]
    pub findings: Vec<mailent_domain::Finding>,
    #[serde(default)]
    pub assets: Vec<mailent_domain::Asset>,
    #[serde(default)]
    pub sessions: Vec<mailent_domain::EmailSession>,
}

#[derive(Debug, Serialize)]
pub struct SyncAssessmentResponse {
    pub synced: bool,
    pub assessment_id: Uuid,
    pub organization_id: Option<Uuid>,
    pub findings_count: usize,
    pub assets_count: usize,
}

pub async fn sync_assessment_handler(
    State(state): State<AppState>,
    ctx: Option<Extension<ExecutionContext>>,
    Json(mut req): Json<SyncAssessmentRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let org_id = ctx
        .as_ref()
        .and_then(|Extension(c)| c.organization_id)
        .or(req.assessment.organization_id);

    if let Some(oid) = org_id {
        req.assessment = req.assessment.with_organization(oid);
        for finding in &mut req.findings {
            finding.organization_id = Some(oid);
        }
        for asset in &mut req.assets {
            asset.organization_id = Some(oid);
        }
    }

    let assessment_id = req.assessment.id;
    let findings_count = req.findings.len();
    let assets_count = req.assets.len();

    state
        .assessments
        .save(&req.assessment)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    for finding in req.findings {
        let _ = state.findings.save(finding).await;
    }

    for asset in req.assets {
        let _ = state.assets.upsert(asset).await;
    }

    for session in req.sessions {
        let _ = state.sessions.save(session).await;
    }

    Ok((
        StatusCode::OK,
        Json(SyncAssessmentResponse {
            synced: true,
            assessment_id,
            organization_id: org_id,
            findings_count,
            assets_count,
        }),
    ))
}

pub async fn list_assessments_handler(
    State(state): State<AppState>,
    ctx: Option<Extension<ExecutionContext>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let org_id = ctx.as_ref().and_then(|Extension(c)| c.organization_id);
    let list = if let Some(org_id) = org_id {
        state.assessments.list_for_org(org_id).await
    } else {
        state.assessments.list_all().await
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(list))
}

pub async fn get_assessment_handler(
    State(state): State<AppState>,
    ctx: Option<Extension<ExecutionContext>>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let org_id = ctx.as_ref().and_then(|Extension(c)| c.organization_id);
    let assessment = if let Some(org_id) = org_id {
        state.assessments.find_by_id_scoped(id, org_id).await
    } else {
        state.assessments.find_by_id(id).await
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Assessment not found".to_string()))?;
    Ok(Json(assessment))
}
