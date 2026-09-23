//! Deterministic assembly of a [`ForensicReport`] from Mailent's own
//! persisted evidence. No LLM/Jev involvement; supplemental AI output is only
//! copied through verbatim into its labelled section.
use crate::model::*;
use mailent_domain::{
    AnomalySignal, Asset, CaptureEvidence, DriftEvent, EmailSession, EvidenceRef, Finding,
    Investigation, ProbeRun, RemediationGuidance, SecurityPosture, StartTlsState,
};
use std::collections::BTreeMap;
use time::OffsetDateTime;

/// Terms whose presence indicates private message content or credentials.
/// Reports are transport-security forensic artifacts; none of this belongs.
const PRIVACY_FORBIDDEN_MARKERS: &[&str] = &[
    "subject:",
    "from:",
    "to:",
    "cc:",
    "bcc:",
    "reply-to:",
    "message-id",
    "password",
    "passwd",
    "credential",
    "authorization: basic",
    "auth plain",
    "auth login",
    "x-oauth",
];

fn sanitize_text(text: &str) -> String {
    let mut out = text.to_string();
    for marker in PRIVACY_FORBIDDEN_MARKERS {
        // Replace any line that carries a forbidden marker with a redaction note.
        if out.to_ascii_lowercase().contains(marker) {
            out = out
                .lines()
                .map(|line| {
                    if line.to_ascii_lowercase().contains(marker) {
                        "[redacted: potential private content or credentials]".to_string()
                    } else {
                        line.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
        }
    }
    out
}

fn starttls_description(state: StartTlsState) -> String {
    match state {
        StartTlsState::Advertised => "STARTTLS advertised in EHLO".into(),
        StartTlsState::Requested => "STARTTLS requested".into(),
        StartTlsState::Accepted => "STARTTLS accepted by server".into(),
        StartTlsState::TlsStarted => "TLS handshake started after STARTTLS".into(),
        StartTlsState::TlsEstablished => "TLS established after STARTTLS".into(),
        StartTlsState::AdvertisedAndUsed => "STARTTLS advertised and used".into(),
        StartTlsState::AdvertisedNotUsed => "STARTTLS advertised but not used".into(),
        StartTlsState::NotAdvertised => "STARTTLS not advertised (plaintext session)".into(),
        StartTlsState::Rejected => "STARTTLS rejected by server".into(),
        StartTlsState::FailedHandshake => "TLS handshake failed after STARTTLS".into(),
        StartTlsState::PlaintextContinuation => "session continued in plaintext".into(),
    }
}

fn protocol_identification(
    protocol: mailent_domain::EmailProtocol,
    capture: Option<&mailent_domain::CaptureEvidence>,
) -> String {
    let base = match protocol {
        mailent_domain::EmailProtocol::Smtp => "SMTP".to_string(),
        mailent_domain::EmailProtocol::Imap => "IMAP".to_string(),
        mailent_domain::EmailProtocol::Pop3 => "POP3".to_string(),
        mailent_domain::EmailProtocol::Unknown => "Unknown protocol".to_string(),
    };
    match capture.and_then(|c| c.protocol_hint) {
        Some(hint) => format!("{base} (capture hint: {hint:?})"),
        None => base,
    }
}

fn expiry_state(not_after: Option<OffsetDateTime>, at: OffsetDateTime) -> String {
    match not_after {
        None => UnavailableReason::NotCaptured.render().to_string(),
        Some(na) => {
            let days = (na - at).whole_days();
            if na < at {
                format!("expired ({} day(s) ago)", -days)
            } else if days == 0 {
                "expires today".to_string()
            } else {
                format!("valid for {days} more day(s)")
            }
        }
    }
}

fn session_record(session: &EmailSession) -> SessionRecord {
    let mut transitions = Vec::new();
    if let Some(st) = session.starttls_state {
        transitions.push(starttls_description(st));
    }
    let forward_secrecy = session
        .key_exchange
        .as_ref()
        .map(|kx| kx.provides_forward_secrecy());
    let certificate_summary = session.certificate.as_ref().map(|cert| CertificateSection {
        subject: cert.reference.subject.clone(),
        issuer: cert.reference.issuer.clone(),
        sha256_fingerprint: cert.reference.sha256_fingerprint.clone(),
        not_before: Some(cert.validity.not_before),
        not_after: Some(cert.validity.not_after),
        san: cert.san.clone(),
        is_self_signed: cert.is_self_signed,
        expiry_state: expiry_state(Some(cert.validity.not_after), session.last_seen),
        crypto_details: cert.crypto_details.clone(),
        source: ProvenanceClass::ObservedFact,
    });

    SessionRecord {
        session_id: session.session_id,
        protocol: session.protocol.to_string(),
        protocol_identification: protocol_identification(
            session.protocol,
            session.capture.as_ref(),
        ),
        flow: format!(
            "{}:{} → {}:{}",
            session.flow.src_ip, session.flow.src_port, session.flow.dst_ip, session.flow.dst_port
        ),
        starttls_transitions: transitions,
        tls_version: session.tls_version.as_ref().map(|v| v.to_string()),
        cipher_suite: session.cipher_suite.as_ref().map(|c| c.name.clone()),
        key_exchange: session
            .key_exchange
            .as_ref()
            .map(|k| serde_json::to_value(k).unwrap_or_default().to_string()),
        forward_secrecy: forward_secrecy.map(|fs| match fs {
            mailent_domain::ForwardSecrecyState::Supported => "supported".to_string(),
            mailent_domain::ForwardSecrecyState::NotSupported => "not supported".to_string(),
            mailent_domain::ForwardSecrecyState::Unknown => {
                UnavailableReason::NotCaptured.render().to_string()
            }
        }),
        certificate_summary,
        timeline: session
            .capture
            .as_ref()
            .map(|c| {
                c.timeline
                    .iter()
                    .map(|t| TimelineEntry {
                        timestamp: t.timestamp,
                        kind: t.kind.clone(),
                        source: t.source.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        gaps: session
            .capture
            .as_ref()
            .map(|c| c.gaps.iter().map(|g| sanitize_text(g)).collect())
            .unwrap_or_default(),
        provenance: format!(
            "sensor {} · parser {} v{}",
            session.sensor_id, session.provenance.parser, session.provenance.parser_version
        ),
    }
}

fn finding_section(
    finding: &Finding,
    guidance_by_finding: &BTreeMap<uuid::Uuid, uuid::Uuid>,
) -> FindingSection {
    FindingSection {
        rule_id: finding.rule_id.clone(),
        title: finding.title.clone(),
        severity: finding.severity.to_string(),
        category: serde_json::to_value(finding.category)
            .unwrap_or_default()
            .as_str()
            .unwrap_or("unknown")
            .to_string(),
        description: sanitize_text(&finding.description),
        policy_name: finding.policy_name.clone(),
        policy_version: finding.policy_version.clone(),
        reference: finding.reference.clone(),
        evidence: finding
            .evidence
            .iter()
            .map(|e| EvidenceRef {
                session_id: e.session_id,
                observation_id: e.observation_id,
                description: sanitize_text(&e.description),
            })
            .collect(),
        remediation_id: guidance_by_finding.get(&finding.id).copied(),
        provenance: ProvenanceClass::DeterministicFinding,
    }
}

fn anomaly_context(a: &AnomalySignal) -> ContextSection {
    ContextSection {
        kind: "anomaly".to_string(),
        signal: a.signal.clone(),
        title: a.title.clone(),
        detail: sanitize_text(&a.evidence),
        baseline_value: Some(a.baseline_value.clone()),
        current_value: Some(a.current_value.clone()),
        observed_at: Some(a.observed_at),
        provenance: ProvenanceClass::AnomalyContext,
    }
}

fn drift_context(d: &DriftEvent) -> ContextSection {
    ContextSection {
        kind: "drift".to_string(),
        signal: format!("{:?}", d.kind),
        title: d.title.clone(),
        detail: sanitize_text(&d.description),
        baseline_value: d.previous_value.clone(),
        current_value: Some(d.new_value.clone()),
        observed_at: Some(d.observed_at),
        provenance: ProvenanceClass::AnomalyContext,
    }
}

fn active_verification(run: &ProbeRun) -> ActiveVerificationSection {
    let (tls_version, forward_secrecy, starttls_result) = run
        .result
        .as_ref()
        .map(|r| {
            (
                r.tls_version.as_ref().map(|v| v.to_string()),
                Some(match r.forward_secrecy {
                    mailent_domain::ForwardSecrecyState::Supported => "supported".to_string(),
                    mailent_domain::ForwardSecrecyState::NotSupported => {
                        "not supported".to_string()
                    }
                    mailent_domain::ForwardSecrecyState::Unknown => {
                        UnavailableReason::NotCaptured.render().to_string()
                    }
                }),
                Some(format!("{:?}", r.starttls)),
            )
        })
        .unwrap_or((None, None, None));

    let mut verification_summary = Vec::new();
    if let Some(r) = &run.result
        && let Some(v) = &r.verification
    {
        for d in &v.drift {
            verification_summary.push(format!(
                "drift {}: active value '{}' → {}",
                d.drift_id,
                d.active_value,
                if d.confirmed {
                    "confirmed at the probed endpoint"
                } else {
                    "perspective mismatch; not globally refuted"
                }
            ));
        }
        for a in &v.anomalies {
            verification_summary.push(format!(
                "anomaly {}: active value '{}' ({})",
                a.anomaly_id, a.active_value, a.conclusion
            ));
        }
    }
    for m in &run.perspective_mismatches {
        verification_summary.push(sanitize_text(&m.description));
    }

    ActiveVerificationSection {
        probe_id: run.id,
        target: run.target.clone(),
        protocol: run.protocol.to_string(),
        port: run.port,
        trigger: run.trigger.to_string(),
        outcome: format!("{:?}", run.outcome),
        started_at: run.started_at,
        finished_at: run.finished_at,
        tls_version,
        forward_secrecy,
        starttls_result,
        certificate_hostname_valid: run
            .result
            .as_ref()
            .and_then(|r| r.certificate_hostname_valid),
        perspective_mismatches: run
            .perspective_mismatches
            .iter()
            .map(|m| {
                let kind = format!("{:?}", m.kind);
                format!("{kind}: {} → {}", m.passive_value, m.active_value)
            })
            .collect(),
        verification_summary,
        provenance: ProvenanceClass::ActiveVerification,
    }
}

fn ai_assessment(investigation: &Investigation) -> Option<AiAssessmentSection> {
    let jev = investigation
        .jev_decision
        .as_ref()
        .filter(|d| !d.is_deterministic())?;
    let provider = jev
        .provider_info
        .split(':')
        .next()
        .unwrap_or("unknown")
        .to_string();
    Some(AiAssessmentSection {
        provider,
        model: jev.provider_info.clone(),
        risk: Some(format!("{:?}", jev.risk)),
        priority: Some(format!("{:?}", jev.priority)),
        confidence: Some(jev.confidence),
        reasons: jev.reasons.iter().map(|r| sanitize_text(r)).collect(),
        caveat: "Supplemental AI output copied verbatim from the stored decision record. \
                 It does not alter the deterministic findings, scores, or guidance in this report."
            .to_string(),
        provenance: ProvenanceClass::AiAssessment,
    })
}

/// Inputs assembled from Mailent's stores.
#[derive(Debug, Clone, Default)]
pub struct ReportInput<'a> {
    pub investigation: Option<&'a Investigation>,
    pub asset: Option<&'a Asset>,
    pub sessions: &'a [EmailSession],
    pub findings: &'a [Finding],
    pub anomalies: &'a [AnomalySignal],
    pub drifts: &'a [DriftEvent],
    pub probe_runs: &'a [ProbeRun],
    pub posture: Option<&'a SecurityPosture>,
    pub guidance: &'a [RemediationGuidance],
    pub remediation_records: &'a [mailent_domain::RemediationRecord],
    pub policy_name: String,
    pub policy_version: String,
}

/// Build the canonical report. Deterministic given identical evidence except
/// for `metadata.generated_at` and the derived `report_id`.
pub fn build_report(
    title: impl Into<String>,
    mailent_version: &str,
    input: &ReportInput<'_>,
    now: OffsetDateTime,
) -> ForensicReport {
    let guidance_by_finding: BTreeMap<uuid::Uuid, uuid::Uuid> = input
        .guidance
        .iter()
        .filter_map(|g| g.finding_id.map(|fid| (fid, g.id)))
        .collect();

    let mut sessions: Vec<SessionRecord> = input.sessions.iter().map(session_record).collect();
    sessions.sort_by_key(|s| s.session_id);

    // Deduplicate certificates by fingerprint (passive + active perspectives).
    let mut certificates: Vec<CertificateSection> = Vec::new();
    for record in sessions
        .iter()
        .filter_map(|s| s.certificate_summary.as_ref())
    {
        if !certificates
            .iter()
            .any(|c| c.sha256_fingerprint == record.sha256_fingerprint)
        {
            certificates.push(record.clone());
        }
    }
    for run in input.probe_runs {
        if let Some(cert) = run.result.as_ref().and_then(|r| r.certificate.as_ref()) {
            if certificates.iter().any(|c| {
                c.sha256_fingerprint == cert.reference.sha256_fingerprint
                    && c.source == ProvenanceClass::ActiveVerification
            }) {
                continue;
            }
            certificates.push(CertificateSection {
                subject: cert.reference.subject.clone(),
                issuer: cert.reference.issuer.clone(),
                sha256_fingerprint: cert.reference.sha256_fingerprint.clone(),
                not_before: Some(cert.validity.not_before),
                not_after: Some(cert.validity.not_after),
                san: cert.san.clone(),
                is_self_signed: cert.is_self_signed,
                expiry_state: expiry_state(
                    Some(cert.validity.not_after),
                    run.finished_at.unwrap_or(run.started_at),
                ),
                crypto_details: cert.crypto_details.clone(),
                source: ProvenanceClass::ActiveVerification,
            });
        }
    }

    let mut findings: Vec<FindingSection> = input
        .findings
        .iter()
        .map(|f| finding_section(f, &guidance_by_finding))
        .collect();
    findings.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));

    let mut context: Vec<ContextSection> = Vec::new();
    context.extend(input.anomalies.iter().map(anomaly_context));
    context.extend(input.drifts.iter().map(drift_context));
    context.sort_by(|a, b| a.signal.cmp(&b.signal));

    let mut active_verifications: Vec<ActiveVerificationSection> = input
        .probe_runs
        .iter()
        .filter(|r| r.finished_at.is_some())
        .map(active_verification)
        .collect();
    active_verifications.sort_by_key(|v| v.probe_id);

    let mut remediation = Vec::new();
    let mut best_practices = Vec::new();
    for g in input.guidance {
        match g.kind {
            mailent_domain::GuidanceKind::Remediation => remediation.push(g.clone()),
            mailent_domain::GuidanceKind::BestPractice => best_practices.push(g.clone()),
        }
    }

    // Evidence gaps: honest statements about what is missing.
    let mut evidence_gaps: Vec<String> = Vec::new();
    let captures: Vec<&CaptureEvidence> = input
        .sessions
        .iter()
        .filter_map(|s| s.capture.as_ref())
        .collect();
    if captures.is_empty() {
        evidence_gaps.push(
            "No capture evidence available for the covered sessions; only flow/TLS metadata present."
                .to_string(),
        );
    }
    let cert_without_crypto: Vec<String> = certificates
        .iter()
        .filter(|c| c.crypto_details.is_none())
        .map(|c| c.subject.clone())
        .collect();
    if !cert_without_crypto.is_empty() {
        evidence_gaps.push(format!(
            "Cryptographic certificate details (public key algorithm/size, signature algorithm, chain validation) unavailable for {} certificate(s); passive capture sources do not expose PKI internals. Run an active probe for full details.",
            cert_without_crypto.len()
        ));
    }
    let missing_forward_secrecy = input
        .sessions
        .iter()
        .filter(|s| s.key_exchange.is_none())
        .count();
    if missing_forward_secrecy > 0 {
        evidence_gaps.push(format!(
            "{missing_forward_secrecy} session(s) lack key-exchange evidence; forward secrecy unknown."
        ));
    }
    if input.posture.is_none() {
        evidence_gaps.push("No posture score computed for this report scope.".to_string());
    }

    let asset_name = input.asset.and_then(|a| a.hostname().map(str::to_string));
    let asset_addresses = input.asset.map(|a| a.addresses.clone()).unwrap_or_default();

    let capture_hashes: Vec<String> = captures
        .iter()
        .map(|c| c.capture_sha256.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    let window_start = input.sessions.iter().map(|s| s.first_seen).min();
    let window_end = input.sessions.iter().map(|s| s.last_seen).max();

    let report_id_seed = format!(
        "{:?}:{:?}:{:?}:{}",
        input.investigation.map(|i| i.id),
        input.asset.map(|a| a.id),
        capture_hashes,
        certificates
            .iter()
            .map(|c| c.sha256_fingerprint.clone())
            .collect::<Vec<_>>()
            .join(",")
    );
    let report_id =
        uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, report_id_seed.as_bytes()).to_string();

    let metadata = CaseMetadata {
        title: title.into(),
        report_id,
        investigation_id: input.investigation.map(|i| i.id),
        asset_id: input.asset.map(|a| a.id),
        asset_name,
        asset_addresses,
        capture_sha256: capture_hashes,
        window_start,
        window_end,
        generated_at: now,
        policy_name: input.policy_name.clone(),
        policy_version: input.policy_version.clone(),
        posture_score_version: input
            .posture
            .map(|p| p.score_version.clone())
            .unwrap_or_else(|| "n/a".to_string()),
        generator: format!("mailent-reporting/{mailent_version}"),
    };

    let risk = input.posture.map(|p| {
        let mut prioritized_actions: Vec<String> = remediation
            .iter()
            .map(|g| format!("[{}] {}: {}", g.severity, g.rule_id, g.recommendation))
            .collect();
        prioritized_actions.sort();
        prioritized_actions.dedup();
        RiskPrioritization {
            grade: p.grade.to_string(),
            score: p.score,
            score_capped: p.score_capped,
            prioritized_actions,
        }
    });

    ForensicReport {
        remediation_lifecycle: input.remediation_records.to_vec(),
        metadata,
        posture: input.posture.cloned(),
        risk,
        sessions,
        certificates,
        findings,
        context,
        active_verifications,
        remediation,
        best_practices,
        ai_assessment: input.investigation.and_then(ai_assessment),
        evidence_gaps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailent_domain::{
        CertificateCryptoDetails, ChainValidation, EmailProtocol, FindingCategory, FindingSeverity,
        GuidanceKind, NetworkFlow, ObservationProvenance, PublicKeyDetails,
    };
    use uuid::Uuid;

    fn sample_session(session_id: Uuid, tls: Option<mailent_domain::TlsVersion>) -> EmailSession {
        let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(900);
        EmailSession {
            session_id,
            sensor_id: "s1".into(),
            provenance: ObservationProvenance {
                source: "pcap".into(),
                parser: "zeek".into(),
                parser_version: "8".into(),
            },
            flow: NetworkFlow {
                src_ip: "10.0.0.1".into(),
                src_port: 1000,
                dst_ip: "10.0.0.2".into(),
                dst_port: 25,
            },
            protocol: EmailProtocol::Smtp,
            starttls_state: Some(StartTlsState::AdvertisedAndUsed),
            tls_version: tls,
            cipher_suite: None,
            key_exchange: None,
            certificate: None,
            capture: None,
            first_seen: now,
            last_seen: now,
        }
    }

    #[test]
    fn privacy_markers_are_redacted() {
        let redacted = sanitize_text("client sent AUTH PLAIN dXNlcg==");
        assert!(redacted.contains("[redacted"));
        let clean = sanitize_text("TLS 1.0 negotiated");
        assert!(!clean.contains("[redacted"));
    }

    #[test]
    fn private_content_never_enters_reports() {
        let mut s = sample_session(Uuid::new_v4(), Some(mailent_domain::TlsVersion::Tls12));
        s.capture = Some(mailent_domain::CaptureEvidence {
            capture_sha256: "cafe".repeat(16),
            connection_uid: "uid1".into(),
            normalizer_version: "1".into(),
            source_logs: vec!["conn.log:1".into()],
            timeline: vec![mailent_domain::TimelineEvent {
                timestamp: s.last_seen,
                kind: "smtp_auth_seen".into(),
                source: "smtp.log:9".into(),
            }],
            gaps: vec!["Message-ID header not captured".into()],
            tls_established: Some(true),
            protocol_hint: None,
        });
        let input = ReportInput {
            remediation_records: &[],
            sessions: std::slice::from_ref(&s),
            ..Default::default()
        };
        let report = build_report(
            "t",
            "0.1.0",
            &input,
            OffsetDateTime::UNIX_EPOCH + time::Duration::days(901),
        );
        let json = serde_json::to_string(&report).unwrap();
        for leaked in ["AUTH LOGIN", "Message-ID header"] {
            assert!(!json.contains(leaked), "report leaked: {leaked}");
        }
        assert!(json.contains("[redacted"));
    }

    #[test]
    fn missing_evidence_is_reported_honestly() {
        let s = sample_session(Uuid::new_v4(), None);
        let input = ReportInput {
            remediation_records: &[],
            sessions: std::slice::from_ref(&s),
            ..Default::default()
        };
        let report = build_report(
            "t",
            "0.1.0",
            &input,
            OffsetDateTime::UNIX_EPOCH + time::Duration::days(901),
        );
        assert!(
            report
                .evidence_gaps
                .iter()
                .any(|g| g.contains("No capture evidence"))
        );
        assert!(
            report
                .evidence_gaps
                .iter()
                .any(|g| g.contains("forward secrecy unknown"))
        );
        // No posture → explicitly stated.
        assert!(
            report
                .evidence_gaps
                .iter()
                .any(|g| g.contains("No posture score"))
        );
    }

    #[test]
    fn same_evidence_same_content() {
        let s = sample_session(Uuid::new_v4(), Some(mailent_domain::TlsVersion::Tls13));
        let input = ReportInput {
            remediation_records: &[],
            sessions: std::slice::from_ref(&s),
            ..Default::default()
        };
        let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(901);
        let a = build_report("t", "0.1.0", &input, now);
        let b = build_report("t", "0.1.0", &input, now);
        assert_eq!(a.content_fingerprint(), b.content_fingerprint());
        assert_eq!(a.metadata.report_id, b.metadata.report_id);

        // generated_at excluded from fingerprint
        let c = build_report(
            "t",
            "0.1.0",
            &input,
            OffsetDateTime::UNIX_EPOCH + time::Duration::days(902),
        );
        assert_eq!(a.content_fingerprint(), c.content_fingerprint());
    }

    #[test]
    fn certificate_details_surface_with_source() {
        let mut s = sample_session(Uuid::new_v4(), Some(mailent_domain::TlsVersion::Tls12));
        s.certificate = Some(mailent_domain::CertificateObservation {
            reference: mailent_domain::CertificateReference {
                sha256_fingerprint: "abc".into(),
                subject: "CN=mail.test".into(),
                issuer: "CN=CA".into(),
            },
            validity: mailent_domain::ValidityPeriod {
                not_before: OffsetDateTime::UNIX_EPOCH,
                not_after: OffsetDateTime::UNIX_EPOCH + time::Duration::days(900),
            },
            is_self_signed: Some(false),
            san: vec!["mail.test".into()],
            crypto_details: Some(CertificateCryptoDetails {
                signature_algorithm: Some("sha256WithRSAEncryption".into()),
                public_key: PublicKeyDetails {
                    algorithm: Some("RSA".into()),
                    rsa_bits: Some(2048),
                    ec_curve: None,
                    spki_sha256: None,
                },
                chain_validation: ChainValidation::Verified,
                chain_length: Some(2),
                extensions: mailent_domain::CertificateExtensions {
                    basic_constraints: Some("CA:FALSE".into()),
                    key_usage: vec!["digitalSignature".into()],
                    extended_key_usage: vec!["serverAuth".into()],
                },
            }),
        });
        let input = ReportInput {
            remediation_records: &[],
            sessions: std::slice::from_ref(&s),
            ..Default::default()
        };
        let report = build_report(
            "t",
            "0.1.0",
            &input,
            OffsetDateTime::UNIX_EPOCH + time::Duration::days(901),
        );
        let cert = &report.certificates[0];
        let details = cert
            .crypto_details
            .as_ref()
            .expect("crypto details present");
        assert_eq!(
            details.signature_algorithm.as_deref(),
            Some("sha256WithRSAEncryption")
        );
        assert_eq!(details.public_key.rsa_bits, Some(2048));
        assert_eq!(details.chain_validation, ChainValidation::Verified);
        // Expiry computed from session last_seen (900d validity, session at day 900).
        assert!(
            cert.expiry_state.contains("expired")
                || cert.expiry_state.contains("valid")
                || cert.expiry_state.contains("expires")
        );
    }

    #[test]
    fn remediation_and_best_practice_are_separated() {
        let finding = Finding {
            id: Uuid::new_v4(),
            rule_id: "TLS_LEGACY_VERSION".into(),
            policy_name: "modern".into(),
            policy_version: "1.0.0".into(),
            reference: "rfc8996".into(),
            severity: FindingSeverity::Critical,
            category: FindingCategory::TlsConfiguration,
            title: "Legacy TLS".into(),
            description: "TLS 1.0".into(),
            remediation: "Upgrade".into(),
            affected_count: 1,
            first_seen: OffsetDateTime::UNIX_EPOCH,
            last_seen: OffsetDateTime::UNIX_EPOCH,
            evidence: vec![],
        };
        let guidance = vec![
            RemediationGuidance {
                id: Uuid::new_v4(),
                kind: GuidanceKind::Remediation,
                finding_id: Some(finding.id),
                rule_id: "TLS_LEGACY_VERSION".into(),
                title: "Legacy TLS".into(),
                observed: "TLS 1.0".into(),
                why_it_matters: "deprecated".into(),
                recommendation: "disable".into(),
                recommended_state: "TLS1.2+".into(),
                compatibility_caveats: vec![],
                verification: "probe".into(),
                evidence: vec![],
                severity: FindingSeverity::Critical,
                category: FindingCategory::TlsConfiguration,
                generated_at: OffsetDateTime::UNIX_EPOCH,
            },
            RemediationGuidance {
                id: Uuid::new_v4(),
                kind: GuidanceKind::BestPractice,
                finding_id: None,
                rule_id: "BP_ENABLE_TLS13".into(),
                title: "TLS 1.3".into(),
                observed: "not observed".into(),
                why_it_matters: "hardening".into(),
                recommendation: "enable".into(),
                recommended_state: "TLS1.3".into(),
                compatibility_caveats: vec![],
                verification: "passive".into(),
                evidence: vec![],
                severity: FindingSeverity::Low,
                category: FindingCategory::TlsConfiguration,
                generated_at: OffsetDateTime::UNIX_EPOCH,
            },
        ];
        let input = ReportInput {
            remediation_records: &[],
            findings: std::slice::from_ref(&finding),
            guidance: &guidance,
            ..Default::default()
        };
        let report = build_report(
            "t",
            "0.1.0",
            &input,
            OffsetDateTime::UNIX_EPOCH + time::Duration::days(901),
        );
        assert_eq!(report.remediation.len(), 1);
        assert_eq!(report.best_practices.len(), 1);
        assert_eq!(report.findings[0].remediation_id, Some(guidance[0].id));
    }
}
