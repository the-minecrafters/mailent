//! Active verification application service. Passive facts and findings are never rewritten.
use crate::state::AppState;
use axum::http::StatusCode;
use mailent_domain::*;
use mailent_probe::{ProbeLimits, SmtpProbeError};
use mailent_storage::StorageError;
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

fn storage_error(e: StorageError) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

pub fn authorized_asset_target(asset: &Asset, scope: &mailent_probe::ProbeScope) -> Option<String> {
    asset
        .primary_name
        .iter()
        .chain(asset.hostnames.iter())
        .chain(asset.addresses.iter())
        .find(|target| scope.is_authorized(target))
        .map(|s| s.trim_end_matches('.').to_ascii_lowercase())
}

pub async fn schedule_probe(
    state: &AppState,
    asset_id: Uuid,
    req: ProbeRequest,
) -> Result<Uuid, (StatusCode, String)> {
    schedule(state, asset_id, req, None).await
}

pub async fn schedule_remediation_probe(
    state: &AppState,
    record: &RemediationRecord,
    probe_id: Uuid,
) -> Result<Uuid, (StatusCode, String)> {
    schedule(
        state,
        record.asset_id,
        ProbeRequest {
            protocol: Some(record.before.protocol),
            port: Some(record.before.flow.dst_port),
            trigger: Some(ProbeTrigger::ManualAnalyst),
            investigation_id: record.investigation_id,
        },
        Some((record, probe_id)),
    )
    .await
}

async fn schedule(
    state: &AppState,
    asset_id: Uuid,
    req: ProbeRequest,
    remediation: Option<(&RemediationRecord, Uuid)>,
) -> Result<Uuid, (StatusCode, String)> {
    let asset = state
        .assets
        .find_by_id(asset_id)
        .await
        .map_err(storage_error)?
        .ok_or((StatusCode::NOT_FOUND, "asset not found".into()))?;
    let target = authorized_asset_target(&asset, &state.probe_config.to_scope())
        .or_else(|| {
            remediation.and_then(|(rec, _)| {
                let candidate = &rec.before.flow.dst_ip;
                if state.probe_config.to_scope().is_authorized(candidate) {
                    Some(candidate.clone())
                } else {
                    None
                }
            })
        })
        .ok_or((
            StatusCode::FORBIDDEN,
            "Live checks are not enabled for this server.".into(),
        ))?;
    let protocol = req.protocol.unwrap_or(EmailProtocol::Smtp);
    let port = req.port.unwrap_or(match protocol {
        EmailProtocol::Smtp => 25,
        EmailProtocol::Imap => 143,
        EmailProtocol::Pop3 => 110,
        EmailProtocol::Unknown => 0,
    });
    if port == 0 || protocol == EmailProtocol::Unknown {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "Choose a supported mail protocol and port.".into(),
        ));
    }
    if let Some(id) = req.investigation_id {
        let investigation = state
            .investigations
            .find_by_id(id)
            .await
            .map_err(storage_error)?
            .ok_or((StatusCode::NOT_FOUND, "Review not found.".into()))?;
        if investigation.asset_id != asset_id {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "This review belongs to a different mail server.".into(),
            ));
        }
    }
    let permit = state.probe_slots.clone().try_acquire_owned().map_err(|_| {
        (
            StatusCode::TOO_MANY_REQUESTS,
            "Too many checks are running. Try again shortly.".into(),
        )
    })?;
    let mut run = ProbeRun::new(
        asset_id,
        target,
        protocol,
        port,
        req.trigger.unwrap_or(ProbeTrigger::ManualAnalyst),
        req.investigation_id,
    );
    if let Some((record, id)) = remediation {
        run.id = id;
        run.remediation_id = Some(record.id);
        run.verification_condition = Some(record.condition);
        // Keep the normal authorized target (and its SNI/identity). The verifier
        // additionally requires DNS to reach the original affected address.
    }
    if !state
        .probes
        .reserve(&run, state.probe_config.cooldown_seconds)
        .await
        .map_err(storage_error)?
    {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "A check is already running or recently finished for this server. Try again shortly."
                .into(),
        ));
    }
    let id = run.id;
    let state = state.clone();
    tokio::spawn(async move {
        let _permit = permit;
        if let Err(e) = execute(&state, run).await {
            tracing::error!(probe_id = %id, error = %e, "Probe persistence/application failed; recovery will mark the unfinished run");
        }
    });
    Ok(id)
}

async fn execute(state: &AppState, mut run: ProbeRun) -> Result<(), StorageError> {
    let scope = state.probe_config.to_scope();
    let limits = ProbeLimits {
        connect_timeout: Duration::from_secs(state.probe_config.timeout_seconds),
        read_timeout: Duration::from_secs(state.probe_config.timeout_seconds),
        ..Default::default()
    };
    let response = if run.protocol == EmailProtocol::Smtp && run.port != 465 {
        mailent_probe::probe_smtp_starttls(&run.target, run.port, "mailent-probe", &limits, &scope)
            .await
    } else if run.protocol == EmailProtocol::Imap && (run.port == 143 || run.port != 993) {
        mailent_probe::probe_imap_starttls(&run.target, run.port, &limits, &scope).await
    } else if run.protocol == EmailProtocol::Pop3 && (run.port == 110 || run.port != 995) {
        mailent_probe::probe_pop3_stls(&run.target, run.port, &limits, &scope).await
    } else {
        mailent_probe::smtp::probe_implicit_tls(&run.target, run.port, &limits, &scope).await
    };
    let (outcome, mut result) = match response {
        Ok(mut result) => {
            enrich_expectations(state, &run, &mut result).await?;
            let outcome = if result.error.is_some() {
                ProbeOutcome::HandshakeError
            } else {
                ProbeOutcome::Success
            };
            (outcome, result)
        }
        Err(e) => {
            let outcome = match e.root() {
                SmtpProbeError::ScopeRejected(_) => ProbeOutcome::ScopeRejected,
                SmtpProbeError::Timeout(_) => ProbeOutcome::Timeout,
                SmtpProbeError::ConnectionRefused => ProbeOutcome::ConnectionRefused,
                SmtpProbeError::TlsHandshakeFailed(_) => ProbeOutcome::HandshakeError,
                _ => ProbeOutcome::InternalError,
            };
            let result = match e {
                SmtpProbeError::Partial { evidence, .. } => *evidence,
                other => ProbeResult::unavailable(&run.target, Some(other.to_string())),
            };
            (outcome, result)
        }
    };
    if run.verification_condition == Some(RemediationCondition::LegacyTlsDisabled)
        && outcome == ProbeOutcome::Success
    {
        for version in [TlsVersion::Tls10, TlsVersion::Tls11] {
            let challenge_limits = ProbeLimits {
                forced_tls_version: Some(version.clone()),
                ..limits
            };
            let challenged = if run.protocol == EmailProtocol::Smtp && run.port != 465 {
                mailent_probe::probe_smtp_starttls(
                    &run.target,
                    run.port,
                    "mailent-probe",
                    &challenge_limits,
                    &scope,
                )
                .await
            } else if run.protocol == EmailProtocol::Imap && (run.port == 143 || run.port != 993) {
                mailent_probe::probe_imap_starttls(&run.target, run.port, &challenge_limits, &scope)
                    .await
            } else if run.protocol == EmailProtocol::Pop3 && (run.port == 110 || run.port != 995) {
                mailent_probe::probe_pop3_stls(&run.target, run.port, &challenge_limits, &scope)
                    .await
            } else {
                mailent_probe::smtp::probe_implicit_tls(
                    &run.target,
                    run.port,
                    &challenge_limits,
                    &scope,
                )
                .await
            };
            result.tls_challenges.push(classify_challenge(
                version,
                challenged,
                result.resolved_ip.as_deref(),
            ));
        }
    }
    run.finish(outcome, Some(result));
    // Persist transport evidence before applying derived context; no network replay on retry.
    state.probes.update(&run).await?;
    apply_evidence(state, &mut run).await?;
    state.probes.update(&run).await?;
    // Merge by probe id so retries are idempotent and analyst status is untouched.
    state.investigations.attach_probe(&run).await?;
    crate::remediation::complete_probe(state, &run).await?;

    if outcome == ProbeOutcome::Success {
        crate::integrations::notify_event(
            state,
            crate::integrations::EventNotification::new(
                IntegrationEventType::VerificationCompleted,
                format!("Verification Completed: {}", run.target),
                format!("Live check completed for {}", run.target),
            )
            .with_asset(run.asset_id, Some(run.target.clone()))
            .with_probe(run.id)
            .with_details(serde_json::to_value(&run).unwrap_or_default()),
        );
    } else {
        crate::integrations::notify_event(
            state,
            crate::integrations::EventNotification::new(
                IntegrationEventType::VerificationFailed,
                format!("Verification Failed: {}", run.target),
                format!("Live check failed for {}: {:?}", run.target, outcome),
            )
            .with_asset(run.asset_id, Some(run.target.clone()))
            .with_probe(run.id)
            .with_details(serde_json::to_value(&run).unwrap_or_default()),
        );
    }

    let _ = crate::api::posture::evaluate_and_record_asset_posture_snapshot(
        state,
        run.asset_id,
        Some("probe_completed"),
    )
    .await;
    Ok(())
}

/// Only an explicit server protocol-version alert establishes refusal. Local
/// OpenSSL limitations, EOF, timeouts and generic handshake failures do not.
fn classify_challenge(
    version: TlsVersion,
    response: Result<ProbeResult, SmtpProbeError>,
    expected_ip: Option<&str>,
) -> TlsChallenge {
    let evidence = match response {
        Ok(evidence) => evidence,
        Err(SmtpProbeError::Partial { evidence, .. }) => *evidence,
        Err(error) => {
            return TlsChallenge {
                version,
                outcome: ChallengeOutcome::Unavailable,
                detail: error.to_string(),
            };
        }
    };
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
        } else if evidence
            .error
            .as_ref()
            .is_some_and(|e| e.contains("alert protocol version") || e.contains("alert number 70"))
        {
            (
                ChallengeOutcome::Rejected,
                evidence.error.unwrap_or_default(),
            )
        } else {
            (
                ChallengeOutcome::Unavailable,
                evidence
                    .error
                    .unwrap_or_else(|| "No explicit protocol refusal captured".into()),
            )
        };
    TlsChallenge {
        version,
        outcome,
        detail,
    }
}

/// Uses already collected intelligence, avoiding unrelated/unauthorized HTTP requests.
async fn enrich_expectations(
    state: &AppState,
    run: &ProbeRun,
    result: &mut ProbeResult,
) -> Result<(), StorageError> {
    let records = state.intelligence.get_tlsa_records(&run.target).await?;
    let records: Vec<_> = records
        .iter()
        .filter(|r| {
            r.mx_host
                .trim_end_matches('.')
                .eq_ignore_ascii_case(&run.target)
                && r.port == run.port
        })
        .collect();
    let mut statuses = vec![];
    for record in records {
        if record.usage != 3
            || OffsetDateTime::now_utc() - record.checked_at > time::Duration::hours(1)
            || result.certificate.is_none()
        {
            statuses.push(DaneStatus::DaneUnverifiable);
            continue;
        }
        statuses.push(mailent_integrations::dane::validate_dane(
            record,
            &result
                .certificate
                .as_ref()
                .expect("certificate checked")
                .reference
                .sha256_fingerprint,
            Some(&result.certificate_der),
            Some(&result.spki_der),
        ));
    }
    result.dane_status = if statuses.contains(&DaneStatus::DaneMatch) {
        DaneStatus::DaneMatch
    } else if statuses.contains(&DaneStatus::DaneUnverifiable) || statuses.is_empty() {
        DaneStatus::DaneUnverifiable
    } else if statuses.contains(&DaneStatus::TlsaWithoutSecureDnssec) {
        DaneStatus::TlsaWithoutSecureDnssec
    } else {
        DaneStatus::DaneMismatch
    };
    result.dane_result = Some(if statuses.is_empty() {
        "Unavailable: no cached TLSA evidence for this endpoint".into()
    } else {
        format!(
            "Cached TLSA expectation: {:?}; only DNSSEC-secured DANE-EE records are verifiable",
            result.dane_status
        )
    });
    if let Some(policy) = state.intelligence.get_mta_sts_policy(&run.target).await? {
        result.mta_sts_mode = Some(policy.mode);
        result.mta_sts_result = Some(
            if OffsetDateTime::now_utc() - policy.checked_at
                > time::Duration::seconds(policy.max_age_seconds.into())
            {
                "Unavailable: cached MTA-STS policy expired".into()
            } else {
                let evaluation = mailent_integrations::mta_sts::evaluate_transport_against_mta_sts(
                    &policy,
                    result.tls_version.is_some(),
                    result.certificate.as_ref(),
                    Some(&run.target),
                    OffsetDateTime::now_utc(),
                );
                if policy.mode != MtaStsMode::None
                    && matches!(
                        evaluation,
                        mailent_integrations::mta_sts::MtaStsValidationResult::Compliant
                    )
                    && (result.certificate_trusted != Some(true)
                        || result.certificate_hostname_valid != Some(true))
                {
                    "CertificateInvalid: active trust or hostname validation failed".into()
                } else {
                    format!("{evaluation:?}")
                }
            },
        );
    } else {
        result.mta_sts_result =
            Some("Unavailable: no cached MTA-STS policy for this domain".into());
    }
    Ok(())
}

pub async fn apply_evidence(state: &AppState, run: &mut ProbeRun) -> Result<(), StorageError> {
    let Some(asset) = state.assets.find_by_id(run.asset_id).await? else {
        return Err(StorageError::Backend("probe asset disappeared".into()));
    };
    let Some(result) = run.result.as_ref() else {
        return Ok(());
    };
    let mut sessions = vec![];
    for addr in &asset.addresses {
        sessions.extend(state.sessions.list_for_asset(addr, 100).await?);
    }
    sessions.retain(|s| {
        s.protocol == run.protocol
            && s.flow.dst_port == run.port
            && s.last_seen <= run.started_at
            && result
                .resolved_ip
                .as_ref()
                .is_some_and(|ip| s.flow.dst_ip == *ip)
    });
    sessions.sort_by_key(|s| std::cmp::Reverse(s.last_seen));
    let passive = sessions.first();
    if let Some(passive) = passive {
        run.perspective_mismatches = compare_perspectives(result, passive);
        run.has_mismatch = !run.perspective_mismatches.is_empty();
    }
    let mut drift = vec![];
    if run.outcome == ProbeOutcome::Success
        && let Some(passive) = passive
    {
        for event in state
            .assets
            .list_drift_events(Some(run.asset_id), 100)
            .await?
        {
            // Confirm only drift backed by the compared session, not historical unrelated changes.
            if event.session_id != Some(passive.session_id) {
                continue;
            }
            let value = match event.kind {
                DriftKind::CertificateChanged => result
                    .certificate
                    .as_ref()
                    .map(|c| c.reference.sha256_fingerprint.clone()),
                DriftKind::NewCertificateIssuer => result
                    .certificate
                    .as_ref()
                    .map(|c| c.reference.issuer.clone()),
                DriftKind::NewTlsVersion => result.tls_version.as_ref().map(ToString::to_string),
                DriftKind::NewCipherSuite => result.cipher_suite.as_ref().map(|c| c.name.clone()),
                _ => None,
            };
            if let Some(value) = value {
                drift.push(ProbeDriftVerification {
                    drift_id: event.id,
                    confirmed: event.new_value == value,
                    active_value: value,
                });
            }
        }
    }
    let anomalies = if let Some(id) = run.investigation_id {
        state
            .investigations
            .find_by_id(id)
            .await?
            .map(|i| i.anomaly_ids)
            .unwrap_or_default()
    } else {
        vec![]
    };
    let mut anomaly_verifications = vec![];
    for anomaly in state
        .baselines
        .list_anomalies(Some(run.asset_id), 100)
        .await?
    {
        if !anomalies.contains(&anomaly.id) {
            continue;
        }
        let (value, corroborates) = match anomaly.signal.as_str() {
            "StarttlsSuccessRateDrop" => (
                format!("{:?}", result.starttls),
                match result.starttls {
                    ProbeStartTlsResult::NotAdvertised
                    | ProbeStartTlsResult::AdvertisedAndRejected => Some(true),
                    ProbeStartTlsResult::AdvertisedAndAccepted => Some(false),
                    _ => None,
                },
            ),
            "NewDaneMismatch" => (
                format!("{:?}", result.dane_status),
                match result.dane_status {
                    DaneStatus::DaneMismatch => Some(true),
                    DaneStatus::DaneMatch => Some(false),
                    _ => None,
                },
            ),
            "InternalExternalInconsistency" => (
                format!(
                    "{} comparable differences",
                    run.perspective_mismatches.len()
                ),
                passive.map(|_| run.has_mismatch),
            ),
            _ => ("No direct comparison for this signal".into(), None),
        };
        anomaly_verifications.push(ProbeAnomalyVerification {
            anomaly_id: anomaly.id,
            active_value: value,
            conclusion: match corroborates {
                Some(true) => "corroborated",
                Some(false) => "perspective_mismatch",
                None => "unavailable",
            }
            .into(),
        });
    }
    if let Some(cert) = &result.certificate {
        let now = run.finished_at.unwrap_or(run.started_at);
        state
            .certificates
            .save(CertificateRecord {
                sha256_fingerprint: cert.reference.sha256_fingerprint.clone(),
                subject: cert.reference.subject.clone(),
                issuer: cert.reference.issuer.clone(),
                sans: cert.san.clone(),
                not_before: cert.validity.not_before,
                not_after: cert.validity.not_after,
                first_seen: now,
                last_seen: now,
                associated_asset_ids: vec![run.asset_id],
            })
            .await?;
    }
    run.result.as_mut().expect("result checked").verification = Some(ProbeVerification {
        passive_session_id: passive.map(|s| s.session_id),
        confidence: if run.outcome != ProbeOutcome::Success {
            "incomplete"
        } else if passive.is_some() {
            "single_endpoint_comparison"
        } else {
            "active_only_no_comparable_passive_session"
        }
        .into(),
        drift,
        anomaly_ids: anomalies,
        anomalies: anomaly_verifications,
    });
    Ok(())
}

/// No automatic replay of interrupted network operations; persist an explicit failure.
pub async fn recover_stale_probes(state: &AppState) -> Result<(), StorageError> {
    for mut run in state.probes.unfinished().await? {
        if OffsetDateTime::now_utc() - run.started_at
            > time::Duration::seconds(state.probe_config.timeout_seconds as i64 * 3 + 30)
        {
            run.finish(ProbeOutcome::InternalError, Some(ProbeResult::unavailable(&run.target, Some("The check was interrupted or its result could not be saved. Wait briefly, then run it again.".into()))));
            state.probes.update(&run).await?;
            state.investigations.attach_probe(&run).await?;
        }
    }
    for mut run in state.probes.list_recent(200).await? {
        if run.finished_at.is_none() {
            continue;
        }
        if run
            .result
            .as_ref()
            .is_some_and(|r| r.verification.is_none())
        {
            apply_evidence(state, &mut run).await?;
            state.probes.update(&run).await?;
        }
        if let Some(id) = run.investigation_id
            && let Some(inv) = state.investigations.find_by_id(id).await?
            && inv.external_intelligence["active_verifications"][run.id.to_string()].is_null()
        {
            state.investigations.attach_probe(&run).await?;
        }
        crate::remediation::complete_probe(state, &run).await?;
    }
    crate::remediation::recover(state).await?;
    Ok(())
}
