#[path = "../../../tests/support/databases.rs"]
mod databases;
use mailent_core::{
    AppState, CoreConfig,
    probes::{apply_evidence, schedule_probe},
};
use mailent_domain::*;
use mailent_probe::{ProbeConfiguration, ProbeLimits};
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

fn configure(state: &mut AppState) {
    state.probe_config = Arc::new(ProbeConfiguration {
        allowed_domains: vec!["127.0.0.1".into()],
        cooldown_seconds: 1,
        ..Default::default()
    });
}
async fn seed(state: &AppState) -> (Asset, Investigation) {
    let now = OffsetDateTime::now_utc();
    let asset = Asset {
        id: Uuid::new_v4(),
        primary_name: Some("127.0.0.1".into()),
        addresses: vec!["127.0.0.1".into()],
        hostnames: vec![],
        identities: vec![],
        endpoints: vec![],
        tls_versions: vec![],
        cipher_suites: vec![],
        certificate_fingerprints: vec![],
        active_findings_count: 0,
        first_seen: now,
        last_seen: now,
        organization_id: None,
    };
    state.assets.upsert(asset.clone()).await.unwrap();
    let inv = Investigation {
        id: Uuid::new_v4(),
        asset_id: asset.id,
        title: "Probe test investigation".into(),
        summary: "Preserve passive evidence".into(),
        status: InvestigationStatus::UnderReview,
        risk: RiskLevel::High,
        priority: PriorityLevel::High,
        finding_ids: vec![],
        drift_event_ids: vec![],
        anomaly_ids: vec![Uuid::new_v4()],
        external_intelligence: serde_json::json!({"passive": "retained"}),
        jev_decision: None,
        first_observed: now,
        last_observed: now,
    };
    state.investigations.save(&inv).await.unwrap();
    (asset, inv)
}
fn request(inv: Uuid) -> ProbeRequest {
    ProbeRequest {
        port: Some(12525),
        protocol: Some(EmailProtocol::Smtp),
        trigger: None,
        investigation_id: Some(inv),
    }
}
async fn completed(state: &AppState, id: Uuid) -> ProbeRun {
    for _ in 0..200 {
        let run = state.probes.find_by_id(id).await.unwrap().unwrap();
        if run.finished_at.is_some() {
            // Background completion merges investigation evidence immediately after result storage.
            if let Some(inv_id) = run.investigation_id {
                let inv = state
                    .investigations
                    .find_by_id(inv_id)
                    .await
                    .unwrap()
                    .unwrap();
                if inv.external_intelligence["active_verifications"][id.to_string()].is_null() {
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                    continue;
                }
            }
            return run;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("probe did not complete");
}

#[tokio::test]
async fn deny_default_scope_and_invalid_investigation() {
    let mut state = AppState::new();
    let (asset, inv) = seed(&state).await;
    assert_eq!(
        schedule_probe(&state, asset.id, request(inv.id))
            .await
            .unwrap_err()
            .0,
        axum::http::StatusCode::FORBIDDEN
    );
    assert!(state.probes.list_recent(10).await.unwrap().is_empty());
    configure(&mut state);
    assert_eq!(
        schedule_probe(&state, asset.id, request(Uuid::new_v4()))
            .await
            .unwrap_err()
            .0,
        axum::http::StatusCode::NOT_FOUND
    );
    let run = ProbeRun::new(
        asset.id,
        "127.0.0.1".into(),
        EmailProtocol::Smtp,
        12525,
        ProbeTrigger::ManualAnalyst,
        Some(inv.id),
    );
    let (a, b) = tokio::join!(
        state.probes.reserve(&run, 300),
        state.probes.reserve(&run, 300)
    );
    assert_ne!(a.unwrap(), b.unwrap());
}

#[tokio::test]
async fn unknown_passive_is_not_a_mismatch_and_drift_is_separate() {
    let state = AppState::new();
    let (asset, inv) = seed(&state).await;
    let obs: NormalizedObservation = serde_json::from_str(include_str!(
        "../../../fixtures/synthetic/smtp_tls10_legacy.json"
    ))
    .unwrap();
    let mut passive = EmailSession::from(&obs);
    passive.session_id = Uuid::new_v4();
    passive.flow.dst_ip = "127.0.0.1".into();
    passive.flow.dst_port = 25;
    passive.starttls_state = None;
    passive.last_seen = OffsetDateTime::now_utc();
    state.sessions.save(passive.clone()).await.unwrap();
    let event = DriftEvent {
        id: Uuid::new_v4(),
        asset_id: asset.id,
        kind: DriftKind::NewTlsVersion,
        title: "Passive TLS regression".into(),
        description: "Observed".into(),
        previous_value: Some("TLSv1.3".into()),
        new_value: "TLSv1.0".into(),
        observed_at: passive.last_seen,
        session_id: Some(passive.session_id),
        assessment_id: None,
        domain: None,
        organization_id: None,
    };
    state.assets.save_drift_event(event.clone()).await.unwrap();
    let mut result = ProbeResult::unavailable("127.0.0.1", None);
    result.resolved_ip = Some("127.0.0.1".into());
    result.tls_version = Some(TlsVersion::Tls13);
    result.starttls = ProbeStartTlsResult::AdvertisedAndAccepted;
    let differences = compare_perspectives(&result, &passive);
    assert_eq!(differences.len(), 1);
    assert_eq!(differences[0].kind, MismatchKind::TlsVersion);
    let mut run = ProbeRun::new(
        asset.id,
        "127.0.0.1".into(),
        EmailProtocol::Smtp,
        25,
        ProbeTrigger::ManualAnalyst,
        Some(inv.id),
    );
    run.finish(ProbeOutcome::Success, Some(result));
    apply_evidence(&state, &mut run).await.unwrap();
    let v = run.result.as_ref().unwrap().verification.as_ref().unwrap();
    assert!(!v.drift[0].confirmed);
    assert_eq!(v.anomaly_ids, inv.anomaly_ids);
    run.result.as_mut().unwrap().tls_version = Some(TlsVersion::Tls10);
    apply_evidence(&state, &mut run).await.unwrap();
    assert!(
        run.result
            .as_ref()
            .unwrap()
            .verification
            .as_ref()
            .unwrap()
            .drift[0]
            .confirmed
    );
    state.investigations.attach_probe(&run).await.unwrap();
    state.investigations.attach_probe(&run).await.unwrap();
    let updated = state
        .investigations
        .find_by_id(inv.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.status, inv.status);
    assert_eq!(updated.external_intelligence["passive"], "retained");
    assert_eq!(
        updated.external_intelligence["active_verifications"]
            .as_object()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        state
            .sessions
            .find_by_id(passive.session_id)
            .await
            .unwrap()
            .unwrap(),
        passive
    );
}

#[tokio::test]
#[ignore = "requires running Postfix/Dovecot lab, PostgreSQL and ClickHouse"]
async fn real_probe_persists_enriches_and_survives_restart() {
    let db = databases::TestDatabases::start()
        .await
        .expect("local test database");
    let config = CoreConfig {
        database_url: Some(db.postgres_url.clone()),
        clickhouse_url: Some(db.clickhouse_url.clone()),
        clickhouse_database: db.clickhouse_database.clone(),
        ..Default::default()
    };
    let mut state = AppState::from_config(&config).await.unwrap();
    configure(&mut state);
    let (asset, inv) = seed(&state).await;
    let active = mailent_probe::probe_smtp_starttls(
        "127.0.0.1",
        12525,
        "mailent-test",
        &ProbeLimits::default(),
        &state.probe_config.to_scope(),
    )
    .await
    .unwrap();
    let cert = active.certificate.as_ref().unwrap();
    state
        .intelligence
        .save_tlsa_records(
            "127.0.0.1",
            &[TlsaRecord {
                domain: "127.0.0.1".into(),
                mx_host: "127.0.0.1".into(),
                port: 12525,
                usage: 3,
                selector: 0,
                matching_type: 1,
                cert_association_data: cert.reference.sha256_fingerprint.clone(),
                dnssec: DnssecState::Secure,
                checked_at: OffsetDateTime::now_utc(),
            }],
        )
        .await
        .unwrap();
    let obs: NormalizedObservation = serde_json::from_str(include_str!(
        "../../../fixtures/synthetic/smtp_tls13_healthy.json"
    ))
    .unwrap();
    let mut passive = EmailSession::from(&obs);
    passive.session_id = Uuid::new_v4();
    passive.flow.dst_ip = "127.0.0.1".into();
    passive.flow.dst_port = 12525;
    passive.certificate = active.certificate.clone();
    passive.tls_version = active.tls_version.clone();
    passive.cipher_suite = active.cipher_suite.clone();
    passive.starttls_state = Some(StartTlsState::AdvertisedAndUsed);
    passive.last_seen = OffsetDateTime::now_utc();
    state.sessions.save(passive).await.unwrap();
    let id = schedule_probe(&state, asset.id, request(inv.id))
        .await
        .unwrap();
    assert_eq!(
        schedule_probe(&state, asset.id, request(inv.id))
            .await
            .unwrap_err()
            .0,
        axum::http::StatusCode::TOO_MANY_REQUESTS
    );
    let run = completed(&state, id).await;
    assert_eq!(run.outcome, ProbeOutcome::Success);
    assert!(!run.has_mismatch);
    assert_eq!(
        run.result.as_ref().unwrap().dane_status,
        DaneStatus::DaneMatch
    );
    assert!(
        !state
            .certificates
            .list_for_asset(asset.id)
            .await
            .unwrap()
            .is_empty()
    );
    let restored = AppState::from_config(&config).await.unwrap();
    assert_eq!(restored.probes.find_by_id(id).await.unwrap().unwrap(), run);
    let investigation = restored
        .investigations
        .find_by_id(inv.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(investigation.status, InvestigationStatus::UnderReview);
    assert_eq!(
        investigation.external_intelligence["active_verifications"][id.to_string()]["id"],
        id.to_string()
    );
    println!(
        "verified persistent probe {id}, asset {}, investigation {}",
        asset.id, inv.id
    );
    db.finish().await;
}

#[derive(Default)]
struct CaptureDecision(std::sync::Mutex<Option<DecisionContext>>);
#[async_trait::async_trait]
impl mailent_decision::DecisionProvider for CaptureDecision {
    async fn assess(
        &self,
        context: DecisionContext,
    ) -> Result<DecisionResult, mailent_decision::DecisionError> {
        *self.0.lock().unwrap() = Some(context);
        Err(mailent_decision::DecisionError::Disabled)
    }
}
#[tokio::test]
async fn next_decision_receives_verified_context_and_automatic_change_is_deduplicated() {
    let mut state = AppState::new();
    configure(&mut state);
    let recorder = Arc::new(CaptureDecision::default());
    state.decision_provider = recorder.clone();
    let (mut asset, inv) = seed(&state).await;
    asset.certificate_fingerprints = vec!["0".repeat(64)];
    state.assets.upsert(asset.clone()).await.unwrap();
    let mut previous = ProbeRun::new(
        asset.id,
        "127.0.0.1".into(),
        EmailProtocol::Smtp,
        25,
        ProbeTrigger::ManualAnalyst,
        Some(inv.id),
    );
    previous.finish(
        ProbeOutcome::Success,
        Some(ProbeResult::unavailable("127.0.0.1", None)),
    );
    state.probes.save(&previous).await.unwrap();
    let mut obs: NormalizedObservation = serde_json::from_str(include_str!(
        "../../../fixtures/synthetic/smtp_cert_expired.json"
    ))
    .unwrap();
    obs.observation_id = Uuid::new_v4();
    obs.timestamp = OffsetDateTime::now_utc();
    obs.flow.dst_ip = "127.0.0.1".into();
    let processed = mailent_core::pipeline::process_observation(&state, obs)
        .await
        .unwrap();
    assert!(
        processed
            .drift_events
            .iter()
            .any(|d| d.kind == DriftKind::CertificateChanged)
    );
    assert_eq!(
        state.probes.list_recent(10).await.unwrap().len(),
        1,
        "automatic trigger must honor existing cooldown"
    );
    assert_eq!(
        recorder.0.lock().unwrap().as_ref().unwrap().metadata["active_verification"]["probe_id"],
        previous.id.to_string()
    );
}

#[tokio::test]
async fn certificate_change_automatically_verifies_same_investigation() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.write_all(b"220 mailent test\r\n").await.unwrap();
        let mut stream = BufReader::new(stream);
        let mut line = String::new();
        stream.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("EHLO "));
        stream
            .get_mut()
            .write_all(b"250 no-upgrade\r\n")
            .await
            .unwrap();
    });
    let mut state = AppState::new();
    configure(&mut state);
    let (mut asset, _) = seed(&state).await;
    asset.certificate_fingerprints = vec!["0".repeat(64)];
    state.assets.upsert(asset.clone()).await.unwrap();
    let mut observation: NormalizedObservation = serde_json::from_str(include_str!(
        "../../../fixtures/synthetic/smtp_cert_expired.json"
    ))
    .unwrap();
    observation.observation_id = Uuid::new_v4();
    observation.timestamp = OffsetDateTime::now_utc();
    observation.flow.dst_ip = "127.0.0.1".into();
    observation.flow.dst_port = port;
    let processed = mailent_core::pipeline::process_observation(&state, observation)
        .await
        .unwrap();
    let inv = processed.investigation.unwrap();
    let runs = state.probes.list_for_asset(asset.id, 10).await.unwrap();
    assert_eq!(runs.len(), 1);
    let run = completed(&state, runs[0].id).await;
    assert_eq!(run.trigger, ProbeTrigger::CertificateChange);
    assert_eq!(run.investigation_id, Some(inv.id));
    assert_eq!(
        run.result.unwrap().starttls,
        ProbeStartTlsResult::NotAdvertised
    );
    assert!(
        state
            .investigations
            .find_by_id(inv.id)
            .await
            .unwrap()
            .unwrap()
            .external_intelligence["active_verifications"][run.id.to_string()]
        .is_object()
    );
    server.await.unwrap();
}
