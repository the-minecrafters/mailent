#[path = "../../../tests/support/databases.rs"]
mod databases;
use mailent_core::{
    AppState, CoreConfig, evidence::EvidenceSnapshot, pipeline::process_observation, remediation,
};
use mailent_domain::*;
use time::OffsetDateTime;
use uuid::Uuid;

async fn seed(state: &AppState, port: u16) -> RemediationRecord {
    let mut obs: NormalizedObservation = serde_json::from_str(include_str!(
        "../../../fixtures/synthetic/smtp_cert_expired.json"
    ))
    .unwrap();
    obs.observation_id = Uuid::new_v4();
    obs.timestamp = OffsetDateTime::now_utc();
    obs.flow.dst_ip = "127.0.0.1".into();
    obs.flow.dst_port = port;
    let result = process_observation(state, obs).await.unwrap();
    let finding = result
        .findings
        .iter()
        .find(|f| f.rule_id == "CERTIFICATE_EXPIRED")
        .unwrap();
    remediation::start(
        state,
        result.asset_id,
        finding.id,
        Some(result.session_id),
        result.investigation.map(|i| i.id),
    )
    .await
    .unwrap()
}
fn certificate_probe(record: &RemediationRecord, valid: bool) -> ProbeRun {
    let mut run = ProbeRun::new(
        record.asset_id,
        record.before.flow.dst_ip.clone(),
        record.before.protocol,
        record.before.flow.dst_port,
        ProbeTrigger::ManualAnalyst,
        record.investigation_id,
    );
    let mut evidence = ProbeResult::unavailable(&run.target, None);
    evidence.resolved_ip = Some(run.target.clone());
    evidence.tls_version = Some(TlsVersion::Tls13);
    evidence.starttls = ProbeStartTlsResult::AdvertisedAndAccepted;
    evidence.certificate = record.before.certificate.clone();
    if valid {
        evidence.certificate.as_mut().unwrap().validity.not_after =
            OffsetDateTime::now_utc() + time::Duration::days(30);
    }
    evidence.certificate_trusted = Some(valid);
    evidence.certificate_hostname_valid = Some(true);
    run.finish(ProbeOutcome::Success, Some(evidence));
    run
}
async fn wait(state: &AppState, id: Uuid) -> RemediationRecord {
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            let r = remediation::get(state, id).await.unwrap();
            if r.state != RemediationState::Verifying {
                return r;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("verification completed")
}
#[tokio::test]
async fn exact_condition_not_just_success_and_endpoint_must_match() {
    let state = AppState::new();
    let mut record = seed(&state, 25).await;
    let failed = certificate_probe(&record, false);
    assert_eq!(
        verify_remediation(&record, &failed).0,
        RemediationState::StillPresent
    );
    let mut fixed = certificate_probe(&record, true);
    assert_eq!(
        verify_remediation(&record, &fixed).0,
        RemediationState::VerifiedFixed
    );
    fixed.result.as_mut().unwrap().resolved_ip = Some("127.0.0.2".into());
    assert_eq!(
        verify_remediation(&record, &fixed).0,
        RemediationState::Inconclusive
    );
    fixed.result.as_mut().unwrap().resolved_ip = Some("127.0.0.1".into());
    record.condition = RemediationCondition::LegacyTlsDisabled;
    assert_eq!(
        verify_remediation(&record, &fixed).0,
        RemediationState::Inconclusive,
        "preferred TLS 1.3 cannot establish TLS 1.0 disabled"
    );
    fixed.result.as_mut().unwrap().tls_challenges = [TlsVersion::Tls10, TlsVersion::Tls11]
        .into_iter()
        .map(|version| TlsChallenge {
            version,
            outcome: ChallengeOutcome::Rejected,
            detail: "server protocol_version alert".into(),
        })
        .collect();
    assert_eq!(
        verify_remediation(&record, &fixed).0,
        RemediationState::VerifiedFixed
    );
    fixed.result.as_mut().unwrap().tls_challenges[0].outcome = ChallengeOutcome::Accepted;
    assert_eq!(
        verify_remediation(&record, &fixed).0,
        RemediationState::StillPresent
    );
    record.condition = RemediationCondition::StartTlsAvailable;
    assert_eq!(
        verify_remediation(&record, &fixed).0,
        RemediationState::VerifiedFixed
    );
    fixed.result.as_mut().unwrap().starttls = ProbeStartTlsResult::NotAdvertised;
    assert_eq!(
        verify_remediation(&record, &fixed).0,
        RemediationState::StillPresent
    );
    fixed.outcome = ProbeOutcome::Timeout;
    assert_eq!(
        verify_remediation(&record, &fixed).0,
        RemediationState::Inconclusive
    );
    record.guidance.kind = GuidanceKind::BestPractice;
    assert!(RemediationCondition::for_guidance(&record.guidance).is_none());
}
#[tokio::test]
async fn unauthorized_connect_never_happens_failure_and_replay_are_safe() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut state = AppState::new();
    let original = seed(&state, port).await;
    let duplicate = remediation::start(
        &state,
        original.asset_id,
        original.finding.id,
        Some(original.before.session_id),
        original.investigation_id,
    )
    .await
    .unwrap();
    assert_eq!(duplicate, original);
    remediation::mark_applied(&state, original.id, Some("local test".into()))
        .await
        .unwrap();
    assert_eq!(
        remediation::request_verification(&state, original.id, Uuid::new_v4())
            .await
            .unwrap_err()
            .0,
        axum::http::StatusCode::FORBIDDEN
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    drop(listener); // authorized probe now gets connection refused, never a successful fix.
    std::sync::Arc::make_mut(&mut state.probe_config).allowed_domains = vec!["127.0.0.1".into()];
    let key = Uuid::new_v4();
    remediation::request_verification(&state, original.id, key)
        .await
        .unwrap();
    let finished = wait(&state, original.id).await;
    assert_eq!(finished.state, RemediationState::Inconclusive);
    assert_eq!(finished.before, original.before);
    assert_eq!(finished.finding, original.finding);
    assert_eq!(
        remediation::request_verification(&state, original.id, key)
            .await
            .unwrap(),
        finished
    );
    assert_eq!(state.probes.list_recent(100).await.unwrap().len(), 1);
    let inv = state
        .investigations
        .find_by_id(original.investigation_id.unwrap())
        .await
        .unwrap()
        .unwrap();
    let records = state
        .training
        .list_recent(Some(inv.id), None, 100)
        .await
        .unwrap();
    assert!(records.iter().any(|r| {
        r.remediation_outcomes
            .get(&key)
            .is_some_and(|l| l.outcome == RemediationState::Inconclusive)
    }));
    let snapshot = EvidenceSnapshot::investigation(&state, inv.id)
        .await
        .unwrap()
        .unwrap();
    let report = snapshot.report(PostureSubjectKind::Investigation, inv.id, &state);
    assert_eq!(report.remediation_lifecycle[0], finished);
    assert!(
        mailent_reporting::render_html(&report)
            .unwrap()
            .contains("Inconclusive")
    );
    assert!(!mailent_reporting::render_pdf(&report).unwrap().is_empty());
    let mut changed = records[0].clone();
    changed.features.asset.endpoint_count += 1;
    assert!(state.training.save(&changed).await.is_err());
}

#[tokio::test]
#[ignore = "requires explicit controlled lab, a freshly captured expired certificate, and SSL_CERT_FILE pointing to its CA"]
async fn real_postfix_fix_cycle_persists_reports_and_training() {
    let capture =
        std::env::var("MAILENT_REMEDIATION_CAPTURE").expect("fresh sensor analysis JSON path");
    let container =
        std::env::var("MAILENT_REMEDIATION_LAB").expect("explicit disposable lab container");
    assert!(
        container.starts_with("mailent-probe-"),
        "only disposable probe lab allowed"
    );
    let db = databases::TestDatabases::start()
        .await
        .expect("local databases required");
    let config = CoreConfig {
        database_url: Some(db.postgres_url.clone()),
        clickhouse_url: Some(db.clickhouse_url.clone()),
        clickhouse_database: db.clickhouse_database.clone(),
        jev_enabled: false,
        ..Default::default()
    };
    let mut state = AppState::from_config(&config).await.unwrap();
    std::sync::Arc::make_mut(&mut state.probe_config).allowed_domains = vec!["127.0.0.1".into()];
    std::sync::Arc::make_mut(&mut state.probe_config).cooldown_seconds = 1;
    let analysis: serde_json::Value =
        serde_json::from_slice(&std::fs::read(capture).unwrap()).unwrap();
    let obs: NormalizedObservation =
        serde_json::from_value(analysis["observations"][0].clone()).unwrap();
    assert_eq!(obs.provenance.source, "pcap");
    assert_eq!(obs.flow.dst_ip, "127.0.0.1");
    let processed = process_observation(&state, obs).await.unwrap();
    let inv = processed.investigation.unwrap();
    let finding = processed
        .findings
        .iter()
        .find(|f| f.rule_id == "CERTIFICATE_EXPIRED")
        .expect("real expired certificate finding");
    let original = remediation::start(
        &state,
        processed.asset_id,
        finding.id,
        Some(processed.session_id),
        Some(inv.id),
    )
    .await
    .unwrap();
    remediation::mark_applied(
        &state,
        original.id,
        Some("verify unchanged lab first".into()),
    )
    .await
    .unwrap();
    let first_key = Uuid::new_v4();
    remediation::request_verification(&state, original.id, first_key)
        .await
        .unwrap();
    let unchanged = wait(&state, original.id).await;
    assert_eq!(
        unchanged.state,
        RemediationState::StillPresent,
        "{unchanged:?}"
    );
    let before_training = state
        .training
        .list_recent(Some(inv.id), None, 100)
        .await
        .unwrap();
    assert!(!before_training.is_empty());
    let analyst = AnalystLabel {
        outcome: AnalystOutcome::AnalystReviewed,
        priority: None,
        labeled_by: None,
        label_source: "analyst".into(),
        note: Some("Controlled certificate rotation".into()),
    };
    state
        .training
        .attach_analyst_label(before_training[0].id, &analyst)
        .await
        .unwrap();
    let output = std::process::Command::new("podman")
        .args([
            "exec",
            &container,
            "python3",
            "/tmp/rotate_certificate.py",
            "valid",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    remediation::mark_applied(
        &state,
        original.id,
        Some("Deployed renewed lab CA certificate".into()),
    )
    .await
    .unwrap();
    let final_key = Uuid::new_v4();
    remediation::request_verification(&state, original.id, final_key)
        .await
        .unwrap();
    let fixed = wait(&state, original.id).await;
    assert_eq!(fixed.state, RemediationState::VerifiedFixed, "{fixed:?}");
    let active = fixed
        .attempts
        .last()
        .unwrap()
        .after
        .as_ref()
        .unwrap()
        .result
        .as_ref()
        .unwrap();
    assert_eq!(active.starttls, ProbeStartTlsResult::AdvertisedAndAccepted);
    assert_eq!(active.certificate_trusted, Some(true));
    assert!(active.cipher_suite.is_some());
    assert_ne!(
        active
            .certificate
            .as_ref()
            .unwrap()
            .reference
            .sha256_fingerprint,
        original
            .before
            .certificate
            .as_ref()
            .unwrap()
            .reference
            .sha256_fingerprint
    );
    assert_eq!(fixed.before, original.before);
    assert_eq!(fixed.finding, original.finding);
    let restored = AppState::from_config(&config).await.unwrap();
    assert_eq!(
        remediation::get(&restored, original.id).await.unwrap(),
        fixed
    );
    assert_eq!(
        remediation::request_verification(&restored, original.id, final_key)
            .await
            .unwrap(),
        fixed,
        "idempotent even after restart without authorization"
    );
    assert_eq!(restored.probes.list_recent(10).await.unwrap().len(), 2);
    assert_eq!(
        restored
            .investigations
            .find_by_id(inv.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        inv.status
    );
    let labeled = restored
        .training
        .find_by_id(before_training[0].id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(labeled.features, before_training[0].features);
    assert_eq!(labeled.analyst_label, Some(analyst));
    assert_eq!(
        labeled.remediation_outcomes[&final_key].outcome,
        RemediationState::VerifiedFixed
    );
    let snapshot = EvidenceSnapshot::investigation(&restored, inv.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.investigation.as_ref().unwrap().id, inv.id);
    let report = snapshot.report(PostureSubjectKind::Investigation, inv.id, &restored);
    assert_eq!(
        report.remediation_lifecycle[0].state,
        RemediationState::VerifiedFixed
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id == "CERTIFICATE_EXPIRED")
    );
    println!(
        "REAL FIX VERIFIED: asset {}, investigation {}, remediation {}, probe {}",
        processed.asset_id,
        inv.id,
        fixed.id,
        fixed.attempts.last().unwrap().probe_id
    );
    drop(restored);
    drop(state);
    db.finish().await;
}

#[tokio::test]
async fn evidence_is_scoped_and_investigation_updates_preserve_analyst_state() {
    let state = AppState::new();
    let record = seed(&state, 25).await;
    let inv_id = record.investigation_id.unwrap();
    state
        .investigations
        .update_status(inv_id, InvestigationStatus::Resolved)
        .await
        .unwrap();
    let mut original = state
        .investigations
        .find_by_id(inv_id)
        .await
        .unwrap()
        .unwrap();
    original.external_intelligence =
        serde_json::json!({"active_verifications": {"test_probe": {"evidence": "retained"}}});
    state.investigations.save(&original).await.unwrap();
    let mut newer = original.clone();
    newer.id = Uuid::new_v4();
    newer.title = "Different investigation".into();
    newer.last_observed += time::Duration::hours(1);
    state.investigations.save(&newer).await.unwrap();
    let exact = EvidenceSnapshot::investigation(&state, inv_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(exact.investigation.as_ref().unwrap().id, inv_id);
    assert_eq!(
        exact
            .report(PostureSubjectKind::Investigation, inv_id, &state)
            .metadata
            .investigation_id,
        Some(inv_id)
    );
    let mut update = original.clone();
    update.status = InvestigationStatus::Open;
    update.finding_ids.clear();
    update.external_intelligence = serde_json::json!({"new": "context"});
    state.investigations.save(&update).await.unwrap();
    let preserved = state
        .investigations
        .find_by_id(inv_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(preserved.status, InvestigationStatus::Resolved);
    assert_eq!(preserved.finding_ids, original.finding_ids);
    assert_eq!(
        preserved.external_intelligence["active_verifications"],
        original.external_intelligence["active_verifications"]
    );
    let mut unrelated: NormalizedObservation = serde_json::from_str(include_str!(
        "../../../fixtures/synthetic/smtp_tls10_legacy.json"
    ))
    .unwrap();
    unrelated.observation_id = Uuid::new_v4();
    unrelated.flow.dst_ip = "192.0.2.44".into();
    unrelated.certificate = None;
    let other = process_observation(&state, unrelated).await.unwrap();
    assert_ne!(other.asset_id, record.asset_id);
    let findings = state.findings.list_for_asset(other.asset_id).await.unwrap();
    assert!(!findings.iter().any(|f| f.id == record.finding.id));
    assert!(
        remediation::start(&state, other.asset_id, record.finding.id, None, None)
            .await
            .is_err()
    );
}

#[tokio::test]
#[ignore = "requires disposable lab accepting legacy TLS and fresh legacy PCAP analysis"]
async fn real_legacy_tls_refusal_is_required_for_a_fix() {
    let capture =
        std::env::var("MAILENT_REMEDIATION_LEGACY_CAPTURE").expect("legacy analysis JSON path");
    let lab = std::env::var("MAILENT_REMEDIATION_LAB").expect("explicit disposable lab");
    assert!(lab.starts_with("mailent-probe-"));
    let mut state = AppState::new();
    std::sync::Arc::make_mut(&mut state.probe_config).allowed_domains = vec!["127.0.0.1".into()];
    std::sync::Arc::make_mut(&mut state.probe_config).cooldown_seconds = 1;
    let analysis: serde_json::Value =
        serde_json::from_slice(&std::fs::read(capture).unwrap()).unwrap();
    let observation: NormalizedObservation =
        serde_json::from_value(analysis["observations"][0].clone()).unwrap();
    assert_eq!(observation.provenance.source, "pcap");
    assert_eq!(observation.tls_version, Some(TlsVersion::Tls10));
    let processed = process_observation(&state, observation).await.unwrap();
    let finding = processed
        .findings
        .iter()
        .find(|f| f.rule_id == "TLS_LEGACY_VERSION")
        .unwrap();
    let original = remediation::start(
        &state,
        processed.asset_id,
        finding.id,
        Some(processed.session_id),
        processed.investigation.map(|i| i.id),
    )
    .await
    .unwrap();
    remediation::mark_applied(&state, original.id, None)
        .await
        .unwrap();
    remediation::request_verification(&state, original.id, Uuid::new_v4())
        .await
        .unwrap();
    let weak = wait(&state, original.id).await;
    assert_eq!(weak.state, RemediationState::StillPresent, "{weak:?}");
    let exec = |args: &[&str]| {
        let result = std::process::Command::new("podman")
            .args(["exec", &lab])
            .args(args)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        String::from_utf8(result.stdout).unwrap()
    };
    let previous = exec(&["postconf", "-h", "smtpd_tls_protocols"]);
    exec(&["postconf", "-e", "smtpd_tls_protocols = >=TLSv1.2"]);
    exec(&["postfix", "reload"]);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    remediation::mark_applied(
        &state,
        original.id,
        Some("Disabled TLS 1.0 and TLS 1.1 in the disposable Postfix lab".into()),
    )
    .await
    .unwrap();
    remediation::request_verification(&state, original.id, Uuid::new_v4())
        .await
        .unwrap();
    let fixed = wait(&state, original.id).await;
    // Restore only the setting this test changed, before asserting the outcome.
    exec(&[
        "postconf",
        "-e",
        &format!("smtpd_tls_protocols = {}", previous.trim()),
    ]);
    exec(&["postfix", "reload"]);
    assert_eq!(fixed.state, RemediationState::VerifiedFixed, "{fixed:?}");
    let challenges = &fixed
        .attempts
        .last()
        .unwrap()
        .after
        .as_ref()
        .unwrap()
        .result
        .as_ref()
        .unwrap()
        .tls_challenges;
    assert_eq!(challenges.len(), 2);
    assert!(
        challenges
            .iter()
            .all(|c| c.outcome == ChallengeOutcome::Rejected)
    );
    assert_eq!(fixed.before, original.before);
    println!("REAL LEGACY FIX VERIFIED: {:?}", challenges);
}
