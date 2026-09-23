use mailent_core::AppState;
use mailent_domain::*;
use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

async fn seed(state: &AppState) -> (Asset, Investigation) {
    let t = now();
    let asset = Asset {
        id: Uuid::new_v4(),
        primary_name: Some("mx1.example.test".into()),
        addresses: vec!["127.0.0.1".into()],
        hostnames: vec!["mx1.example.test".into()],
        identities: vec![],
        endpoints: vec![AssetEndpoint {
            protocol: EmailProtocol::Smtp,
            port: 25,
            tls_versions: vec![TlsVersion::Tls12],
            cipher_suites: vec!["ECDHE-RSA-AES256-GCM-SHA384".into()],
            first_seen: t,
            last_seen: t,
        }],
        tls_versions: vec![TlsVersion::Tls12],
        cipher_suites: vec!["ECDHE-RSA-AES256-GCM-SHA384".into()],
        certificate_fingerprints: vec!["ab".repeat(32)],
        active_findings_count: 1,
        first_seen: t,
        last_seen: t,
    };
    state.assets.upsert(asset.clone()).await.unwrap();
    let inv = Investigation {
        id: Uuid::new_v4(),
        asset_id: asset.id,
        title: "Training slice investigation".into(),
        summary: "Derived feature snapshot at decision time".into(),
        status: InvestigationStatus::UnderReview,
        risk: RiskLevel::High,
        priority: PriorityLevel::High,
        finding_ids: vec![],
        drift_event_ids: vec![],
        anomaly_ids: vec![],
        external_intelligence: serde_json::json!({}),
        jev_decision: None,
        first_observed: t,
        last_observed: t,
    };
    state.investigations.save(&inv).await.unwrap();
    (asset, inv)
}

fn session(asset_id: Uuid) -> EmailSession {
    let t = now();
    let _ = asset_id;
    EmailSession {
        session_id: Uuid::new_v4(),
        sensor_id: "test-sensor".into(),
        provenance: ObservationProvenance {
            source: "test".into(),
            parser: "synthetic".into(),
            parser_version: "1".into(),
        },
        flow: NetworkFlow {
            src_ip: "10.1.2.3".into(),
            src_port: 45678,
            dst_ip: "127.0.0.1".into(),
            dst_port: 25,
        },
        protocol: EmailProtocol::Smtp,
        starttls_state: Some(StartTlsState::AdvertisedAndUsed),
        tls_version: Some(TlsVersion::Tls12),
        cipher_suite: Some(CipherSuite {
            id: None,
            name: "ECDHE-RSA-AES256-GCM-SHA384".into(),
        }),
        key_exchange: Some(KeyExchange::Ecdhe),
        certificate: None,
        capture: None,
        first_seen: t,
        last_seen: t,
    }
}

#[allow(clippy::too_many_arguments)]
fn context<'a>(
    inv: &'a Investigation,
    asset: &'a Asset,
    session: &'a EmailSession,
    findings: &'a [Finding],
    drift: &'a [DriftEvent],
    anomalies: &'a [AnomalySignal],
    baseline: Option<&'a AssetBaseline>,
    active: Option<&'a ProbeRun>,
    jev: Option<&'a DecisionResult>,
    domain: Option<&'a str>,
) -> mailent_core::training::CaptureContext<'a> {
    mailent_core::training::CaptureContext {
        inv,
        asset,
        session,
        findings,
        drift_events: drift,
        anomalies,
        baseline,
        dane_status: Some(DaneStatus::DaneMismatch),
        mta_sts_mode: Some(MtaStsMode::Enforce),
        mta_sts_failed: true,
        mta_sts_enforced: true,
        tlsa_record_count: 2,
        active_verification: active,
        jev_decision: jev,
        delivery_domain: domain,
        captured_at: now(),
    }
}

fn baseline(asset_id: Uuid) -> AssetBaseline {
    let t = now();
    let mut dist = HashMap::new();
    dist.insert("TLSv1.3".to_string(), 0.75);
    AssetBaseline {
        asset_id,
        sample_count: 42,
        window_start: t - time::Duration::hours(24),
        window_end: t,
        generated_at: t,
        coverage: 0.9,
        tls_version_distribution: dist.clone(),
        cipher_distribution: HashMap::new(),
        key_exchange_distribution: HashMap::new(),
        certificate_fingerprints: vec![],
        certificate_issuers: vec![],
        starttls_success_rate: 0.95,
        handshake_failure_rate: 0.02,
        peer_set: vec!["peer-a".into(), "peer-b".into()],
        ports: vec![25],
        session_frequency_per_hour: 3.1,
    }
}

#[tokio::test]
async fn record_created_from_investigation_context() {
    let state = AppState::new();
    let (asset, inv) = seed(&state).await;
    let s = session(asset.id);
    let record = mailent_core::training::capture_training(
        &state,
        &context(
            &inv,
            &asset,
            &s,
            &[],
            &[],
            &[],
            None,
            None,
            None,
            Some("example.test"),
        ),
    )
    .await
    .unwrap();
    assert_eq!(record.investigation_id, inv.id);
    assert_eq!(record.asset_id, asset.id);
    assert_eq!(
        record.feature_schema_version,
        TRAINING_FEATURE_SCHEMA_VERSION
    );
    assert_eq!(record.features.asset.endpoint_count, 1);
    assert_eq!(record.features.tls.protocol, EmailProtocol::Smtp);
    assert!(record.features.delivery.mta_sts_failed);
    assert_eq!(record.features.delivery.tlsa_record_count, 2);
    let stored = state.training.find_by_id(record.id).await.unwrap().unwrap();
    assert_eq!(stored, record);
}

#[tokio::test]
async fn probe_evidence_is_included_as_derived_features() {
    let state = AppState::new();
    let (asset, inv) = seed(&state).await;
    let s = session(asset.id);
    let mut result = ProbeResult::unavailable("127.0.0.1", None);
    result.tls_version = Some(TlsVersion::Tls13);
    result.starttls = ProbeStartTlsResult::AdvertisedAndAccepted;
    result.verification = Some(ProbeVerification {
        passive_session_id: Some(s.session_id),
        confidence: "high".into(),
        drift: vec![ProbeDriftVerification {
            drift_id: Uuid::new_v4(),
            active_value: "TLSv1.3".into(),
            confirmed: true,
        }],
        anomaly_ids: vec![],
        anomalies: vec![],
    });
    let mut run = ProbeRun::new(
        asset.id,
        "127.0.0.1".into(),
        EmailProtocol::Smtp,
        25,
        ProbeTrigger::CertificateChange,
        Some(inv.id),
    );
    run.finish(ProbeOutcome::Success, Some(result));
    run.attach_mismatches(vec![PerspectiveMismatch {
        kind: MismatchKind::TlsVersion,
        passive_value: "TLSv1.2".into(),
        active_value: "TLSv1.3".into(),
        description: "version drifted".into(),
    }]);
    let record = mailent_core::training::capture_training(
        &state,
        &context(
            &inv,
            &asset,
            &s,
            &[],
            &[],
            &[],
            None,
            Some(&run),
            None,
            None,
        ),
    )
    .await
    .unwrap();
    let probe = record.features.probe.as_ref().unwrap();
    assert_eq!(probe.protocol, EmailProtocol::Smtp);
    assert_eq!(probe.port, 25);
    assert_eq!(probe.outcome, "success");
    assert_eq!(probe.starttls, "advertised");
    assert_eq!(probe.verified_drift_count, 1);
    assert!(probe.tls_version.as_deref().is_some());
    assert!(probe.has_mismatch);
    assert_eq!(probe.mismatch_kinds, vec![MismatchKind::TlsVersion]);
}

#[tokio::test]
async fn jev_decision_included_as_teacher_signal() {
    let state = AppState::new();
    let (asset, inv) = seed(&state).await;
    let s = session(asset.id);
    let decision = DecisionResult {
        risk: RiskLevel::High,
        anomalous: true,
        human_review: true,
        priority: PriorityLevel::High,
        confidence: 0.9,
        provider_info: "test-model-v1".into(),
        reasons: vec!["certificate expired".into()],
    };
    let record = mailent_core::training::capture_training(
        &state,
        &context(
            &inv,
            &asset,
            &s,
            &[],
            &[],
            &[],
            None,
            None,
            Some(&decision),
            None,
        ),
    )
    .await
    .unwrap();
    let jev = record.features.jev.as_ref().unwrap();
    assert_eq!(jev.provider, "test-model-v1");
    assert_eq!(jev.role, "teacher");
    assert_eq!(jev.risk, RiskLevel::High);
    assert!(jev.anomalous);
    let label = record.automated_label.as_ref().unwrap();
    assert_eq!(label.source, "jev/test-model-v1");
    assert_eq!(label.risk, Some(RiskLevel::High));
}

#[tokio::test]
async fn analyst_label_is_attachable_and_kept_separate() {
    let state = AppState::new();
    let (asset, inv) = seed(&state).await;
    let s = session(asset.id);
    let record = mailent_core::training::capture_training(
        &state,
        &context(&inv, &asset, &s, &[], &[], &[], None, None, None, None),
    )
    .await
    .unwrap();
    assert!(record.analyst_label.is_none());
    let label = AnalystLabel {
        outcome: AnalystOutcome::RealMisconfiguration,
        priority: Some(PriorityLevel::High),
        label_source: "analyst".into(),
        note: Some("confirmed via independent check".into()),
        labeled_by: Some("analyst@mailent.test".into()),
    };
    state
        .training
        .attach_analyst_label(record.id, &label)
        .await
        .unwrap();
    let updated = state.training.find_by_id(record.id).await.unwrap().unwrap();
    let attached = updated.analyst_label.as_ref().unwrap();
    assert_eq!(attached.outcome, AnalystOutcome::RealMisconfiguration);
    assert_eq!(
        attached.note.as_deref(),
        Some("confirmed via independent check")
    );
    assert!(updated.labeled_at.is_some());
    // analyst label distinct from automated label
    assert!(updated.automated_label.is_none());
    assert!(updated.analyst_label.is_some());
}

#[tokio::test]
async fn original_feature_snapshot_preserved_verbatim_after_labeling() {
    let state = AppState::new();
    let (asset, inv) = seed(&state).await;
    let s = session(asset.id);
    let mut anomalies = vec![AnomalySignal {
        id: Uuid::new_v4(),
        asset_id: asset.id,
        signal: "tls_version_shift".into(),
        title: "TLS version shift".into(),
        current_value: "TLSv1.0".into(),
        baseline_value: "TLSv1.2".into(),
        deviation: 2.4,
        confidence: 0.87,
        evidence: "regression observed".into(),
        observed_at: now(),
    }];
    let record = mailent_core::training::capture_training(
        &state,
        &context(
            &inv,
            &asset,
            &s,
            &[],
            &[],
            &anomalies,
            None,
            None,
            None,
            None,
        ),
    )
    .await
    .unwrap();
    let before = serde_json::to_value(&record.features).unwrap();
    state
        .training
        .attach_analyst_label(
            record.id,
            &AnalystLabel {
                outcome: AnalystOutcome::Dismissed,
                priority: None,
                label_source: "analyst".into(),
                note: None,
                labeled_by: None,
            },
        )
        .await
        .unwrap();
    let updated = state.training.find_by_id(record.id).await.unwrap().unwrap();
    let after = serde_json::to_value(&updated.features).unwrap();
    assert_eq!(before, after, "original snapshot must not change");
    // mutating the input afterwards must not mutate the stored snapshot
    anomalies.clear();
    assert!(anomalies.is_empty());
    let still = state.training.find_by_id(record.id).await.unwrap().unwrap();
    assert_eq!(still.features.anomalies.len(), 1);
}

#[tokio::test]
async fn sensitive_or_raw_data_excluded_from_snapshot() {
    let state = AppState::new();
    let (asset, inv) = seed(&state).await;
    let s = session(asset.id);
    let t = now();
    let findings = vec![Finding {
        id: Uuid::new_v4(),
        rule_id: "mail.sts.enforce".into(),
        policy_name: "mta-sts".into(),
        policy_version: "1.0".into(),
        reference: "r-1".into(),
        severity: FindingSeverity::Critical,
        category: FindingCategory::TlsConfiguration,
        title: "Enforce but failure".into(),
        description: "embedded address 203.0.113.4 and credential here".into(),
        remediation: "fix".into(),
        affected_count: 1,
        first_seen: t,
        last_seen: t,
        evidence: vec![EvidenceRef {
            session_id: Some(s.session_id),
            observation_id: None,
            description: "raw smtp conversation 203.0.113.4 auth PASSWD".into(),
        }],
    }];
    let record = mailent_core::training::capture_training(
        &state,
        &context(
            &inv,
            &asset,
            &s,
            &findings,
            &[],
            &[],
            None,
            None,
            None,
            None,
        ),
    )
    .await
    .unwrap();
    assert_eq!(record.features.policy.len(), 1);
    let p = &record.features.policy[0];
    assert_eq!(p.rule_id, "mail.sts.enforce");
    assert_eq!(p.category, FindingCategory::TlsConfiguration);
    let json = serde_json::to_string(&record).unwrap();
    assert!(!json.contains("203.0.113.4"));
    assert!(!json.contains("PASSWD"));
    assert!(!json.contains("raw smtp conversation"));
    assert!(!json.contains("10.1.2.3"), "src ip must not leak");
}

#[tokio::test]
async fn baseline_and_schema_version_persisted() {
    let state = AppState::new();
    let (asset, inv) = seed(&state).await;
    let s = session(asset.id);
    let b = baseline(asset.id);
    let record = mailent_core::training::capture_training(
        &state,
        &context(&inv, &asset, &s, &[], &[], &[], Some(&b), None, None, None),
    )
    .await
    .unwrap();
    assert_eq!(
        record.feature_schema_version,
        TRAINING_FEATURE_SCHEMA_VERSION
    );
    let fb = record.features.baseline.as_ref().unwrap();
    assert_eq!(fb.sample_count, 42);
    assert_eq!(fb.peer_count, 2);
    assert_eq!(fb.ports, vec![25]);
    assert_eq!(fb.tls_version_distribution["TLSv1.3"], 0.75);
}

#[tokio::test]
async fn pipeline_automatically_captures_training_record() {
    let mut state = AppState::new();
    state.probe_config = std::sync::Arc::new(mailent_probe::ProbeConfiguration {
        allowed_domains: vec!["127.0.0.1".into()],
        cooldown_seconds: 3600,
        ..Default::default()
    });
    let (asset, _) = seed(&state).await;
    let mut obs: NormalizedObservation = serde_json::from_str(include_str!(
        "../../../fixtures/synthetic/smtp_cert_expired.json"
    ))
    .unwrap();
    obs.observation_id = Uuid::new_v4();
    obs.timestamp = now();
    obs.flow.dst_ip = "127.0.0.1".into();
    let processed = mailent_core::pipeline::process_observation(&state, obs)
        .await
        .unwrap();
    let inv = processed
        .investigation
        .expect("cert-expired should correlate");
    assert!(!processed.findings.is_empty() || !processed.drift_events.is_empty());
    let records = state
        .training
        .list_recent(Some(inv.id), Some(asset.id), 10)
        .await
        .unwrap();
    assert_eq!(records.len(), 1);
    let rec = &records[0];
    assert_eq!(rec.feature_schema_version, TRAINING_FEATURE_SCHEMA_VERSION);
    assert_eq!(rec.investigation_id, inv.id);
    assert_eq!(rec.asset_id, asset.id);
    let _ = rec;
}

#[tokio::test]
async fn deterministic_fallback_is_not_an_ai_teacher_or_report_assessment() {
    let state = AppState::new();
    let (asset, mut inv) = seed(&state).await;
    let s = session(asset.id);
    let decision = DecisionResult {
        risk: RiskLevel::High,
        priority: PriorityLevel::High,
        anomalous: false,
        human_review: true,
        confidence: 1.0,
        provider_info: DETERMINISTIC_DECISION_PROVIDER.into(),
        reasons: vec!["Deterministic policy".into()],
    };
    let record = mailent_core::training::capture_training(
        &state,
        &context(
            &inv,
            &asset,
            &s,
            &[],
            &[],
            &[],
            None,
            None,
            Some(&decision),
            None,
        ),
    )
    .await
    .unwrap();
    assert!(record.features.jev.is_none());
    assert_eq!(
        record.automated_label.unwrap().source,
        DETERMINISTIC_DECISION_PROVIDER
    );
    inv.jev_decision = Some(decision);
    let input = mailent_reporting::ReportInput {
        investigation: Some(&inv),
        ..Default::default()
    };
    assert!(
        mailent_reporting::build_report("test", "test", &input, now())
            .ai_assessment
            .is_none()
    );
}
