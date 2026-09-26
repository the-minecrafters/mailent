use std::time::Duration;
use mailent_domain::{
    ChallengeOutcome, EmailProtocol, Finding, FindingCategory, GuidanceKind, NetworkFlow,
    ObservationProvenance, ProbeOutcome, ProbeResult, ProbeRun, ProbeTrigger, RemediationAttempt,
    RemediationCondition, RemediationGuidance, RemediationRecord, RemediationState, StartTlsState,
    TlsChallenge, TlsVersion, verify_remediation,
};
use mailent_probe::{AuthorizedDomain, ProbeLimits, ProbeScope, SmtpProbeError};
use time::OffsetDateTime;
use uuid::Uuid;

use super::adapter::RemediationPlan;

fn classify_challenge(
    version: TlsVersion,
    response: Result<ProbeResult, SmtpProbeError>,
    expected_ip: Option<&str>,
) -> TlsChallenge {
    let (evidence, root_err) = match response {
        Ok(evidence) => (evidence, None),
        Err(SmtpProbeError::Partial { evidence, source }) => (*evidence, Some(source.to_string())),
        Err(error) => {
            let err_str = error.to_string().to_ascii_lowercase();
            let is_refused = err_str.contains("protocol version")
                || err_str.contains("alert number 70")
                || err_str.contains("alert number 40")
                || err_str.contains("handshake failure")
                || err_str.contains("handshakefailed")
                || err_str.contains("unsupported protocol")
                || err_str.contains("tls alert")
                || err_str.contains("connection reset")
                || err_str.contains("broken pipe");

            let outcome = if is_refused {
                ChallengeOutcome::Rejected
            } else {
                ChallengeOutcome::Unavailable
            };
            return TlsChallenge {
                version,
                outcome,
                detail: error.to_string(),
            };
        }
    };

    let err_str = evidence
        .error
        .as_deref()
        .or(root_err.as_deref())
        .unwrap_or("")
        .to_ascii_lowercase();

    let (outcome, detail) =
        if evidence.resolved_ip.as_deref() != expected_ip || expected_ip.is_none() {
            (
                ChallengeOutcome::Unavailable,
                "Challenge did not reach the same address".into(),
            )
        } else if evidence.tls_version.as_ref() == Some(&version) {
            (
                ChallengeOutcome::Accepted,
                "Constrained legacy TLS handshake established".into(),
            )
        } else if err_str.contains("alert protocol version")
            || err_str.contains("alert number 70")
            || err_str.contains("alert number 40")
            || err_str.contains("handshake failure")
            || err_str.contains("handshakefailed")
            || err_str.contains("protocol version")
            || err_str.contains("tls alert")
            || err_str.contains("connection reset")
            || err_str.contains("broken pipe")
        {
            (
                ChallengeOutcome::Rejected,
                if !err_str.is_empty() {
                    err_str
                } else {
                    "Server refused legacy handshake".into()
                },
            )
        } else {
            (
                ChallengeOutcome::Unavailable,
                if !err_str.is_empty() {
                    err_str
                } else {
                    "No explicit protocol refusal captured".into()
                },
            )
        };
    TlsChallenge {
        version,
        outcome,
        detail,
    }
}

pub async fn run_active_verification(
    plan: &RemediationPlan,
    finding: Option<&Finding>,
) -> Result<(RemediationState, String, ProbeRun, RemediationRecord), String> {
    let (host, port_str) = plan
        .target_endpoint
        .split_once(':')
        .unwrap_or(("127.0.0.1", "25"));
    let port: u16 = port_str.parse().unwrap_or(25);

    let scope = ProbeScope::new(vec![AuthorizedDomain {
        domain: "*".to_string(),
        authorization_ref: "cli-fix-local".to_string(),
    }]);

    let limits = ProbeLimits {
        connect_timeout: Duration::from_secs(5),
        read_timeout: Duration::from_secs(10),
        ..Default::default()
    };

    println!("  [5/5] 󱐋 Running active verification challenge probes against {host}:{port}…");

    // Primary probe
    let response = match plan.protocol {
        EmailProtocol::Smtp => {
            mailent_probe::probe_smtp_starttls(host, port, "mailent-probe", &limits, &scope).await
        }
        EmailProtocol::Imap => {
            mailent_probe::probe_imap_starttls(host, port, &limits, &scope).await
        }
        EmailProtocol::Pop3 => {
            mailent_probe::probe_pop3_stls(host, port, &limits, &scope).await
        }
        _ => mailent_probe::probe_implicit_tls(host, port, &limits, &scope).await,
    };

    let (outcome, mut result) = match response {
        Ok(res) => {
            let is_cert_only_error = res.error.as_ref().map_or(false, |e| {
                e.contains("certificate")
                    || e.contains("unknown issuer")
                    || e.contains("self-signed")
                    || e.contains("expired")
            });
            let outcome = if res.error.is_none() || (is_cert_only_error && res.tls_version.is_some()) {
                ProbeOutcome::Success
            } else {
                ProbeOutcome::HandshakeError
            };
            (outcome, res)
        }
        Err(e) => {
            let outcome = match e.root() {
                SmtpProbeError::ScopeRejected(_) => ProbeOutcome::ScopeRejected,
                SmtpProbeError::Timeout(_) => ProbeOutcome::Timeout,
                SmtpProbeError::ConnectionRefused => ProbeOutcome::ConnectionRefused,
                SmtpProbeError::TlsHandshakeFailed(_) => ProbeOutcome::HandshakeError,
                _ => ProbeOutcome::InternalError,
            };
            let res = match e {
                SmtpProbeError::Partial { evidence, .. } => *evidence,
                other => ProbeResult::unavailable(host, Some(other.to_string())),
            };
            (outcome, res)
        }
    };

    let condition = match plan.rule_id.as_str() {
        "TLS_LEGACY_VERSION" => RemediationCondition::LegacyTlsDisabled,
        "STARTTLS_MISSING" => RemediationCondition::StartTlsAvailable,
        "NO_FORWARD_SECRECY" => RemediationCondition::ForwardSecrecyOnly,
        _ => RemediationCondition::CertificateValid,
    };

    // If LegacyTlsDisabled and primary succeeded (or TLS negotiated), run explicit TLS 1.0 and 1.1 challenges
    if condition == RemediationCondition::LegacyTlsDisabled
        && (outcome == ProbeOutcome::Success || result.tls_version.is_some())
    {
        for version in [TlsVersion::Tls10, TlsVersion::Tls11] {
            let challenge_limits = ProbeLimits {
                forced_tls_version: Some(version.clone()),
                ..limits
            };

            let challenged = match plan.protocol {
                EmailProtocol::Smtp => {
                    mailent_probe::probe_smtp_starttls(
                        host,
                        port,
                        "mailent-probe",
                        &challenge_limits,
                        &scope,
                    )
                    .await
                }
                EmailProtocol::Imap => {
                    mailent_probe::probe_imap_starttls(host, port, &challenge_limits, &scope).await
                }
                EmailProtocol::Pop3 => {
                    mailent_probe::probe_pop3_stls(host, port, &challenge_limits, &scope).await
                }
                _ => {
                    mailent_probe::probe_implicit_tls(host, port, &challenge_limits, &scope).await
                }
            };

            let challenge = classify_challenge(
                version.clone(),
                challenged,
                result.resolved_ip.as_deref(),
            );

            let status_desc = match challenge.outcome {
                ChallengeOutcome::Rejected => "\x1b[32m󰄬 REJECTED (server refused legacy protocol)\x1b[0m",
                ChallengeOutcome::Accepted => "\x1b[31m󰅖 ACCEPTED (server allowed legacy version)\x1b[0m",
                ChallengeOutcome::Unavailable => "\x1b[33m󰀦 INCONCLUSIVE\x1b[0m",
            };
            println!("        • {version:?} challenge: {status_desc}");

            result.tls_challenges.push(challenge);
        }
    }

    let asset_id = Uuid::new_v5(&Uuid::NAMESPACE_DNS, host.as_bytes());
    let mut probe_run = ProbeRun::new(
        asset_id,
        host.to_string(),
        plan.protocol,
        port,
        ProbeTrigger::ManualAnalyst,
        None,
    );
    probe_run.verification_condition = Some(condition);
    probe_run.finish(outcome, Some(result));

    let resolved_ip = probe_run
        .result
        .as_ref()
        .and_then(|r| r.resolved_ip.clone())
        .unwrap_or_else(|| host.to_string());

    let before_session = mailent_domain::EmailSession {
        session_id: Uuid::new_v4(),
        sensor_id: "cli-fix".to_string(),
        provenance: ObservationProvenance {
            source: "cli-fix".to_string(),
            parser: "mailent-probe".to_string(),
            parser_version: "0.1.4".to_string(),
        },
        flow: NetworkFlow {
            src_ip: "127.0.0.1".into(),
            src_port: 49152,
            dst_ip: resolved_ip,
            dst_port: port,
        },
        protocol: plan.protocol,
        starttls_state: Some(StartTlsState::NotAdvertised),
        tls_version: Some(TlsVersion::Tls10),
        cipher_suite: None,
        key_exchange: None,
        certificate: None,
        capture: None,
        first_seen: OffsetDateTime::now_utc(),
        last_seen: OffsetDateTime::now_utc(),
    };

    let finding_record = finding.cloned().unwrap_or_else(|| Finding {
        id: Uuid::new_v4(),
        rule_id: plan.rule_id.clone(),
        policy_name: "modern".to_string(),
        policy_version: "1.1.0".to_string(),
        reference: "rfc8996".to_string(),
        severity: plan.severity,
        category: FindingCategory::TlsConfiguration,
        title: plan.finding_title.clone(),
        description: format!("Remediation target finding {}", plan.rule_id),
        remediation: plan.changes.iter().map(|c| c.description.clone()).collect::<Vec<_>>().join("; "),
        affected_count: 1,
        first_seen: OffsetDateTime::now_utc(),
        last_seen: OffsetDateTime::now_utc(),
        evidence: vec![],
        organization_id: None,
    });

    let guidance = RemediationGuidance {
        id: Uuid::new_v4(),
        kind: GuidanceKind::Remediation,
        finding_id: Some(finding_record.id),
        rule_id: plan.rule_id.clone(),
        title: plan.finding_title.clone(),
        observed: format!("Verified on local {}", plan.service_kind),
        why_it_matters: "Security policy requirement".into(),
        recommendation: plan.changes.iter().map(|c| format!("{}: {}", c.parameter, c.new_value)).collect::<Vec<_>>().join(", "),
        recommended_state: "Modern TLS exclusively".into(),
        compatibility_caveats: vec![],
        verification: "Live challenge probes".into(),
        evidence: vec![],
        severity: plan.severity,
        category: FindingCategory::TlsConfiguration,
        generated_at: OffsetDateTime::now_utc(),
    };

    let mut record = RemediationRecord {
        id: Uuid::new_v4(),
        asset_id,
        investigation_id: None,
        finding: finding_record,
        guidance,
        before: before_session,
        condition,
        state: RemediationState::Verifying,
        revision: 1,
        started_at: OffsetDateTime::now_utc(),
        applied_at: Some(OffsetDateTime::now_utc()),
        analyst_note: Some(format!("Applied via `mailent fix` on {}", plan.service_kind)),
        attempts: vec![],
    };

    let (verification_state, explanation) = verify_remediation(&record, &probe_run);
    record.state = verification_state;
    record.attempts.push(RemediationAttempt {
        request_id: Uuid::new_v4(),
        probe_id: probe_run.id,
        requested_at: OffsetDateTime::now_utc(),
        completed_at: probe_run.finished_at,
        outcome: Some(verification_state),
        explanation: explanation.clone(),
        after: Some(probe_run.clone()),
    });

    Ok((verification_state, explanation, probe_run, record))
}
