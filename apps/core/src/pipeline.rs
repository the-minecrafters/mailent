use mailent_correlation::FindingCorrelator;
use mailent_domain::{
    AnomalySignal, Asset, AssetEndpoint, AssetIdentity, CertificateRecord, DriftEvent, DriftKind,
    EmailSession, Finding, FindingCandidate, ForwardSecrecyState, Investigation,
    NormalizedObservation,
};
use mailent_policy::evaluate;
use mailent_storage::StorageError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::state::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessedObservationResult {
    pub session_id: Uuid,
    pub asset_id: Uuid,
    pub candidates: Vec<FindingCandidate>,
    pub findings: Vec<Finding>,
    pub drift_events: Vec<DriftEvent>,
    pub anomalies: Vec<AnomalySignal>,
    pub investigation: Option<Investigation>,
}

pub async fn process_observation(
    state: &AppState,
    observation: NormalizedObservation,
) -> Result<ProcessedObservationResult, StorageError> {
    let session = EmailSession::from(&observation);

    // 1. Analytical persistence: Store observation and session
    state.observations.save(observation.clone()).await?;
    state.sessions.save(session.clone()).await?;

    // 2. Policy evaluation & finding correlation
    let candidates = evaluate(&session, &state.policy_pack);
    let findings = FindingCorrelator::correlate_session(&session, &candidates);

    // 3. Asset discovery & correlation
    let target_ip = session.flow.dst_ip.clone();
    let port = session.flow.dst_port;
    let protocol = session.protocol;
    let now = session.last_seen;

    // Extract hostname candidates from certificate if present
    let (cert_fp, cert_subject, cert_issuer, cert_sans) = match &session.certificate {
        Some(c) => (
            Some(c.reference.sha256_fingerprint.clone()),
            Some(c.reference.subject.clone()),
            Some(c.reference.issuer.clone()),
            c.san.clone(),
        ),
        None => (None, None, None, Vec::new()),
    };

    let mut hostname_candidates = cert_sans.clone();
    if let Some(ref subj) = cert_subject {
        // e.g. CN=mail.example.com
        if let Some(cn) = subj.split("CN=").nth(1) {
            let cn_clean = cn.split(',').next().unwrap_or("").trim().to_string();
            if !cn_clean.is_empty() && !hostname_candidates.contains(&cn_clean) {
                hostname_candidates.push(cn_clean);
            }
        }
    }

    // Look up existing asset by IP or hostname
    let mut existing_asset = state.assets.find_by_address_or_identity(&target_ip).await?;
    if existing_asset.is_none() {
        for h in &hostname_candidates {
            if let Some(a) = state.assets.find_by_address_or_identity(h).await? {
                existing_asset = Some(a);
                break;
            }
        }
    }

    let mut drift_events = Vec::new();

    let asset = match existing_asset {
        Some(mut a) => {
            // Check for configuration drift:
            // a) New TLS Version
            if let Some(ref tls_ver) = session.tls_version
                && !a.tls_versions.contains(tls_ver)
            {
                drift_events.push(DriftEvent {
                    id: Uuid::new_v4(),
                    asset_id: a.id,
                    kind: DriftKind::NewTlsVersion,
                    title: "New TLS Version Detected".to_string(),
                    description: format!("Endpoint {target_ip}:{port} observed with {tls_ver}"),
                    previous_value: a.tls_versions.last().map(|v| v.to_string()),
                    new_value: tls_ver.to_string(),
                    observed_at: now,
                    session_id: Some(session.session_id),
                    assessment_id: None,
                    domain: None,
                    organization_id: None,
                });
                a.tls_versions.push(tls_ver.clone());
            }

            // b) New Cipher Suite
            if let Some(ref cs) = session.cipher_suite
                && !a.cipher_suites.contains(&cs.name)
            {
                drift_events.push(DriftEvent {
                    id: Uuid::new_v4(),
                    asset_id: a.id,
                    kind: DriftKind::NewCipherSuite,
                    title: "New Cipher Suite Observed".to_string(),
                    description: format!("Endpoint {target_ip}:{port} negotiated {}", cs.name),
                    previous_value: a.cipher_suites.last().cloned(),
                    new_value: cs.name.clone(),
                    observed_at: now,
                    session_id: Some(session.session_id),
                    assessment_id: None,
                    domain: None,
                    organization_id: None,
                });
                a.cipher_suites.push(cs.name.clone());
            }

            // c) Forward Secrecy Lost
            let current_pfs = session
                .key_exchange
                .as_ref()
                .map(|k| k.provides_forward_secrecy())
                .unwrap_or(ForwardSecrecyState::Unknown);
            if current_pfs == ForwardSecrecyState::NotSupported {
                // Check if any previous cipher had PFS
                let had_pfs = a
                    .cipher_suites
                    .iter()
                    .any(|c| c.contains("DHE") || c.contains("ECDHE"));
                if had_pfs {
                    drift_events.push(DriftEvent {
                        id: Uuid::new_v4(),
                        asset_id: a.id,
                        kind: DriftKind::ForwardSecrecyLost,
                        title: "Forward Secrecy Lost".to_string(),
                        description: format!("Session on {target_ip}:{port} negotiated cipher without Forward Secrecy"),
                        previous_value: Some("PFS Enabled".to_string()),
                        new_value: "PFS Disabled".to_string(),
                        observed_at: now,
                        session_id: Some(session.session_id),
                        assessment_id: None,
                        domain: None,
                        organization_id: None,
                    });
                }
            }

            // d) Certificate Changed / New Issuer
            if let Some(ref fp) = cert_fp
                && !a.certificate_fingerprints.contains(fp)
            {
                drift_events.push(DriftEvent {
                    id: Uuid::new_v4(),
                    asset_id: a.id,
                    kind: DriftKind::CertificateChanged,
                    title: "Certificate Changed".to_string(),
                    description: format!(
                        "New certificate fingerprint observed on {target_ip}:{port}"
                    ),
                    previous_value: a.certificate_fingerprints.last().cloned(),
                    new_value: fp.clone(),
                    observed_at: now,
                    session_id: Some(session.session_id),
                    assessment_id: None,
                    domain: None,
                    organization_id: None,
                });
                a.certificate_fingerprints.push(fp.clone());

                if let Some(ref issuer) = cert_issuer {
                    drift_events.push(DriftEvent {
                        id: Uuid::new_v4(),
                        asset_id: a.id,
                        kind: DriftKind::NewCertificateIssuer,
                        title: "New Certificate Issuer".to_string(),
                        description: format!("Certificate issued by {issuer}"),
                        previous_value: None,
                        new_value: issuer.clone(),
                        observed_at: now,
                        session_id: Some(session.session_id),
                        assessment_id: None,
                        domain: None,
                        organization_id: None,
                    });
                }
            }

            // e) New Endpoint
            let endpoint_exists = a
                .endpoints
                .iter()
                .any(|e| e.protocol == protocol && e.port == port);
            if !endpoint_exists {
                drift_events.push(DriftEvent {
                    id: Uuid::new_v4(),
                    asset_id: a.id,
                    kind: DriftKind::NewEndpoint,
                    title: "New Service Endpoint Discovered".to_string(),
                    description: format!("New endpoint active on {target_ip}:{port} ({protocol})"),
                    previous_value: None,
                    new_value: format!("{protocol}:{port}"),
                    observed_at: now,
                    session_id: Some(session.session_id),
                    assessment_id: None,
                    domain: None,
                    organization_id: None,
                });
                a.endpoints.push(AssetEndpoint {
                    protocol,
                    port,
                    tls_versions: session.tls_version.clone().into_iter().collect(),
                    cipher_suites: session
                        .cipher_suite
                        .as_ref()
                        .map(|c| vec![c.name.clone()])
                        .unwrap_or_default(),
                    first_seen: now,
                    last_seen: now,
                });
            } else if let Some(ep) = a
                .endpoints
                .iter_mut()
                .find(|e| e.protocol == protocol && e.port == port)
            {
                ep.last_seen = now;
                if let Some(ref tv) = session.tls_version
                    && !ep.tls_versions.contains(tv)
                {
                    ep.tls_versions.push(tv.clone());
                }
                if let Some(ref cs) = session.cipher_suite
                    && !ep.cipher_suites.contains(&cs.name)
                {
                    ep.cipher_suites.push(cs.name.clone());
                }
            }

            // Update addresses and hostnames
            if !a.addresses.contains(&target_ip) {
                a.addresses.push(target_ip.clone());
            }
            for h in &hostname_candidates {
                if !a.hostnames.contains(h) {
                    a.hostnames.push(h.clone());
                }
                if a.primary_name.is_none() {
                    a.primary_name = Some(h.clone());
                }
            }

            a.last_seen = now;
            a
        }
        None => {
            // Discover new Asset
            let new_id = Uuid::new_v4();
            let primary_name = hostname_candidates.first().cloned();
            Asset {
                id: new_id,
                primary_name,
                addresses: vec![target_ip.clone()],
                hostnames: hostname_candidates.clone(),
                identities: hostname_candidates
                    .iter()
                    .map(|h| AssetIdentity {
                        kind: "hostname".to_string(),
                        value: h.clone(),
                        first_seen: now,
                        last_seen: now,
                    })
                    .collect(),
                endpoints: vec![AssetEndpoint {
                    protocol,
                    port,
                    tls_versions: session.tls_version.clone().into_iter().collect(),
                    cipher_suites: session
                        .cipher_suite
                        .as_ref()
                        .map(|c| vec![c.name.clone()])
                        .unwrap_or_default(),
                    first_seen: now,
                    last_seen: now,
                }],
                tls_versions: session.tls_version.clone().into_iter().collect(),
                cipher_suites: session
                    .cipher_suite
                    .as_ref()
                    .map(|c| vec![c.name.clone()])
                    .unwrap_or_default(),
                certificate_fingerprints: cert_fp.clone().into_iter().collect(),
                active_findings_count: findings.len(),
                first_seen: now,
                last_seen: now,
                organization_id: None,
            }
        }
    };

    let asset_id = asset.id;

    // 4. Save drift events
    for drift in &drift_events {
        state.assets.save_drift_event(drift.clone()).await?;
    }

    // 5. Save/upsert asset
    state.assets.upsert(asset.clone()).await?;

    // 6. Save certificate record if present
    if let (Some(fp), Some(subj), Some(iss)) = (cert_fp, cert_subject, cert_issuer) {
        let (not_before, not_after) = match &session.certificate {
            Some(c) => (c.validity.not_before, c.validity.not_after),
            None => (now, now + time::Duration::days(365)),
        };
        let cert_record = CertificateRecord {
            sha256_fingerprint: fp,
            subject: subj,
            issuer: iss,
            sans: cert_sans,
            not_before,
            not_after,
            first_seen: now,
            last_seen: now,
            associated_asset_ids: vec![asset_id],
        };
        state.certificates.save(cert_record).await?;
    }

    // 7. Persist findings
    for finding in &findings {
        state.findings.save(finding.clone()).await?;
        state.findings.link_asset(finding.id, asset_id).await?;
        crate::integrations::notify_event(
            state,
            crate::integrations::EventNotification::new(
                mailent_domain::IntegrationEventType::FindingConfirmed,
                format!("Finding Confirmed: {}", finding.title),
                &finding.description,
            )
            .with_asset(asset_id, asset.primary_name.clone())
            .with_finding(finding.id)
            .with_details(serde_json::to_value(finding).unwrap_or_default()),
        );
    }

    // 8. Baseline & Anomaly Detection
    let primary_domain = if let Some(ref cert) = session.certificate {
        cert.san.first().cloned().or_else(|| {
            cert.reference.subject.split("CN=").nth(1).and_then(|cn| {
                let clean = cn.split(',').next().unwrap_or("").trim();
                if !clean.is_empty() {
                    Some(clean.to_string())
                } else {
                    None
                }
            })
        })
    } else {
        asset
            .primary_name
            .clone()
            .or_else(|| asset.hostnames.first().cloned())
    };

    let (dane_status, mta_sts_failed, mta_sts_enforced, mta_sts_mode, tlsa_record_count) =
        if let Some(ref dom) = primary_domain {
            let base_domain = if let Some((_, parent)) = dom.split_once('.') {
                if parent.contains('.') {
                    parent.to_string()
                } else {
                    dom.clone()
                }
            } else {
                dom.clone()
            };

            let mta_sts = match state
                .intelligence
                .get_mta_sts_policy(dom)
                .await
                .unwrap_or(None)
            {
                Some(p) => Some(p),
                None => state
                    .intelligence
                    .get_mta_sts_policy(&base_domain)
                    .await
                    .unwrap_or(None),
            };

            let mta_sts_mode = mta_sts.as_ref().map(|p| p.mode);

            let (mta_failed, mta_enforced) = if let Some(ref sts) = mta_sts {
                let enforced = sts.mode == mailent_domain::MtaStsMode::Enforce;
                let val_res = mailent_integrations::evaluate_session_against_mta_sts(
                    sts,
                    &session,
                    session.certificate.as_ref(),
                    Some(dom),
                );
                let failed = matches!(
                    val_res,
                    mailent_integrations::MtaStsValidationResult::MxPatternMismatch { .. }
                        | mailent_integrations::MtaStsValidationResult::StartTlsNotNegotiated
                        | mailent_integrations::MtaStsValidationResult::CertificateExpired
                        | mailent_integrations::MtaStsValidationResult::CertificateInvalid(_)
                );
                (failed, enforced)
            } else {
                (false, false)
            };

            let tlsa_records = {
                let recs = state
                    .intelligence
                    .get_tlsa_records(dom)
                    .await
                    .unwrap_or_default();
                if recs.is_empty() {
                    state
                        .intelligence
                        .get_tlsa_records(&base_domain)
                        .await
                        .unwrap_or_default()
                } else {
                    recs
                }
            };

            let tlsa_record_count = tlsa_records.len();

            let dane_st = if let Some(ref cert) = session.certificate {
                if !tlsa_records.is_empty() {
                    let any_match = tlsa_records.iter().any(|tlsa| {
                        mailent_integrations::validate_dane(
                            tlsa,
                            &cert.reference.sha256_fingerprint,
                            None,
                            None,
                        ) == mailent_domain::DaneStatus::DaneMatch
                    });
                    if any_match {
                        Some(mailent_domain::DaneStatus::DaneMatch)
                    } else {
                        Some(mailent_domain::DaneStatus::DaneMismatch)
                    }
                } else {
                    None
                }
            } else {
                None
            };

            (
                dane_st,
                mta_failed,
                mta_enforced,
                mta_sts_mode,
                tlsa_record_count,
            )
        } else {
            (None, false, false, None, 0)
        };

    let intel_anomalies = mailent_baseline::detect_intelligence_anomalies(
        asset_id,
        &session,
        dane_status,
        mta_sts_failed,
        None,
        mta_sts_enforced,
    );

    let existing_baseline = state.baselines.get_baseline(asset_id).await.unwrap_or(None);
    let mut anomalies = if let Some(ref b) = existing_baseline {
        state.baseline_analyzer.analyze_session(b, &session)
    } else {
        Vec::new()
    };
    anomalies.extend(intel_anomalies);

    for anomaly in &anomalies {
        state.baselines.save_anomaly(anomaly).await?;
    }

    // 9. Update asset baseline
    let mut historical = state
        .sessions
        .list_for_asset(target_ip.as_str(), 100)
        .await
        .unwrap_or_default();
    if !historical
        .iter()
        .any(|s| s.session_id == session.session_id)
    {
        historical.push(session.clone());
    }
    let win_start = historical.iter().map(|s| s.first_seen).min().unwrap_or(now);
    let win_end = historical.iter().map(|s| s.last_seen).max().unwrap_or(now);
    let new_baseline =
        mailent_baseline::calculate_baseline(asset_id, &historical, win_start, win_end);
    let _ = state.baselines.save_baseline(&new_baseline).await;

    let active_verification = state
        .probes
        .list_for_asset(asset_id, 20)
        .await?
        .into_iter()
        .find(|p| {
            p.finished_at.is_some()
                && p.protocol == session.protocol
                && p.port == session.flow.dst_port
        });
    // 10. Jev decision assessment
    let jev_decision = if !findings.is_empty() || !drift_events.is_empty() || !anomalies.is_empty()
    {
        let ctx = mailent_domain::DecisionContext {
            session_id: session.session_id,
            findings: candidates.clone(),
            metadata: serde_json::json!({
                "asset_id": asset_id,
                "active_verification": active_verification.as_ref().map(|p| serde_json::json!({
                    "probe_id": p.id, "verified_at": p.finished_at, "outcome": p.outcome,
                    "target": p.target, "port": p.port, "protocol": p.protocol,
                    "resolved_ip": p.result.as_ref().and_then(|r| r.resolved_ip.as_ref()),
                    "perspective_mismatches": p.perspective_mismatches,
                    "verification": p.result.as_ref().and_then(|r| r.verification.as_ref()),
                    "tls_version": p.result.as_ref().and_then(|r| r.tls_version.as_ref()),
                    "starttls": p.result.as_ref().map(|r| r.starttls),
                    "dane_status": p.result.as_ref().map(|r| r.dane_status),
                    "mta_sts_result": p.result.as_ref().and_then(|r| r.mta_sts_result.as_ref()),
                })),
                "anomalies_count": anomalies.len(),
                "drifts_count": drift_events.len(),
                "dane_status": dane_status,
                "mta_sts_failed": mta_sts_failed,
                "mta_sts_enforced": mta_sts_enforced,
            }),
        };

        let (res, src) = match state.decision_provider.assess(ctx.clone()).await {
            Ok(r) => {
                let source = if r.provider_info.starts_with("jev:") {
                    "jev"
                } else {
                    "deterministic_fallback"
                };
                (r, source.to_string())
            }
            Err(e) => {
                tracing::warn!("Decision assessment fallback used: {e}");
                (
                    mailent_decision::JevProvider::deterministic_fallback(&ctx),
                    "deterministic_fallback".to_string(),
                )
            }
        };

        let record = mailent_domain::DecisionRecord {
            id: Uuid::new_v4(),
            session_id: Some(session.session_id),
            asset_id: Some(asset_id),
            provider: src,
            model: res.provider_info.clone(),
            decision: res.clone(),
            latency_ms: 0,
            created_at: now,
        };
        let _ = state.decisions.save_record(&record).await;
        Some(res)
    } else {
        None
    };

    // 11. Investigation Correlation
    let intel_summary = serde_json::json!({
        "domain": primary_domain,
        "dane_status": dane_status,
        "mta_sts_enforced": mta_sts_enforced,
        "mta_sts_failed": mta_sts_failed,
    });

    let investigation = mailent_correlation::InvestigationCorrelator::correlate_incident(
        asset_id,
        &findings,
        &drift_events,
        &anomalies,
        intel_summary,
        jev_decision,
        now,
    );

    if let Some(ref inv) = investigation {
        state.investigations.save(inv).await?;
        crate::integrations::notify_event(
            state,
            crate::integrations::EventNotification::new(
                mailent_domain::IntegrationEventType::InvestigationCreated,
                format!("Review created: {}", inv.title),
                &inv.summary,
            )
            .with_asset(asset_id, asset.primary_name.clone())
            .with_investigation(inv.id)
            .with_details(serde_json::to_value(inv).unwrap_or_default()),
        );
        // Best-effort: capture a versioned training record at decision time.
        let capture_ctx = crate::training::CaptureContext {
            inv,
            asset: &asset,
            session: &session,
            findings: &findings,
            drift_events: &drift_events,
            anomalies: &anomalies,
            baseline: existing_baseline.as_ref(),
            dane_status,
            mta_sts_mode,
            mta_sts_failed,
            mta_sts_enforced,
            tlsa_record_count,
            active_verification: active_verification.as_ref(),
            jev_decision: inv.jev_decision.as_ref(),
            delivery_domain: primary_domain.as_deref(),
            captured_at: now,
        };
        if let Err(e) = crate::training::capture_training(state, &capture_ctx).await {
            tracing::warn!(%asset_id, "training capture skipped: {e}");
        }
        let trigger = if drift_events
            .iter()
            .any(|d| d.kind == mailent_domain::DriftKind::CertificateChanged)
        {
            Some(mailent_domain::ProbeTrigger::CertificateChange)
        } else if anomalies
            .iter()
            .any(|a| a.signal == "StarttlsSuccessRateDrop")
        {
            Some(mailent_domain::ProbeTrigger::StartTlsRegression)
        } else if anomalies
            .iter()
            .any(|a| a.signal == "InternalExternalInconsistency")
        {
            Some(mailent_domain::ProbeTrigger::InternalExternalInconsistency)
        } else {
            None
        };
        if let Some(trigger) = trigger {
            let req = mailent_domain::ProbeRequest {
                port: Some(session.flow.dst_port),
                protocol: Some(session.protocol),
                trigger: Some(trigger),
                investigation_id: Some(inv.id),
            };
            if let Err((status, reason)) = crate::probes::schedule_probe(state, asset_id, req).await
            {
                tracing::info!(%asset_id, %status, %reason, "Automatic verification was not scheduled");
            }
        }
    }

    let _ = crate::api::posture::evaluate_and_record_asset_posture_snapshot(
        state,
        asset_id,
        Some("observation_processed"),
    )
    .await;

    Ok(ProcessedObservationResult {
        session_id: session.session_id,
        asset_id,
        candidates,
        findings,
        drift_events,
        anomalies,
        investigation,
    })
}
