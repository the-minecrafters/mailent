use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use mailent_core::{AppState, api::create_router, auth::protect};
use mailent_domain::{
    AssessmentRecord, DEFAULT_ORG_ID, DiscoveredEndpoint, InfrastructureMetadata,
};
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;

async fn setup_test_app() -> (AppState, axum::Router) {
    let state = AppState::new();
    let app = protect(create_router(state.clone()), None, state.clone());
    (state, app)
}

async fn create_and_approve_device(app: &axum::Router, name: &str, org_id: Uuid) -> (String, Uuid) {
    // 1. Create Challenge
    let req_body = serde_json::json!({
        "device_name": name,
        "hostname": "test-host",
        "platform": "linux",
        "architecture": "x86_64"
    });

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/devices/authorize/challenge")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let challenge_res: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let code = challenge_res["code"].as_str().unwrap();

    // 2. Approve Challenge
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/devices/authorize/{code}/approve"))
                .header("x-mailent-org", org_id.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // 3. Poll Challenge for Token
    let poll_body = serde_json::json!({ "code": code });
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/devices/authorize/poll")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&poll_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let poll_res: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let token = poll_res["token"].as_str().unwrap().to_string();
    let device_id = Uuid::parse_str(poll_res["device_id"].as_str().unwrap()).unwrap();

    (token, device_id)
}

fn create_sample_infra_assessment(
    domain: &str,
    score: f32,
    grade: &str,
    endpoints: Vec<DiscoveredEndpoint>,
    created_at: OffsetDateTime,
) -> AssessmentRecord {
    let infra = InfrastructureMetadata {
        target_domain: domain.to_string(),
        discovered_endpoints: endpoints,
        scan_start: created_at - time::Duration::seconds(5),
        scan_end: created_at,
        discovery_evidence: Vec::new(),
    };

    let asset_id = Uuid::new_v5(&Uuid::NAMESPACE_OID, domain.as_bytes());

    AssessmentRecord::new_infrastructure(
        Uuid::new_v4(),
        format!("{domain} Infrastructure Assessment"),
        infra,
        created_at,
        vec!["SMTP".to_string()],
        vec![],
        vec![],
        vec![asset_id],
        vec![],
        score,
        grade.to_string(),
        vec![],
        "LOW".to_string(),
        "Complies with baseline".to_string(),
        0.95,
        serde_json::json!({}),
    )
}

async fn api(
    app: &axum::Router,
    token: &str,
    method: &str,
    path: &str,
    value: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(value.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&body)
            .unwrap_or_else(|_| serde_json::json!({"text": String::from_utf8_lossy(&body)})),
    )
}

#[tokio::test]
async fn installation_status_and_online_remote_gate_are_separate() {
    let (state, app) = setup_test_app().await;
    let (token, id) = create_and_approve_device(&app, "CLI", DEFAULT_ORG_ID).await;
    let scan = serde_json::json!({"domain": "mailent.test", "device_id": id});
    assert_eq!(
        api(&app, &token, "POST", "/api/v1/scans/device", scan.clone())
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        api(
            &app,
            &token,
            "POST",
            "/api/v1/devices/status",
            serde_json::json!({"version":"0.1.4", "zeek_version":"8.0.4"})
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, listed) = api(
        &app,
        &token,
        "GET",
        "/api/v1/devices",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(listed[0]["readiness"], "ready");
    assert_eq!(listed[0]["remote_online"], false);
    assert!(listed[0]["last_sync_at"].is_null());
    assert_eq!(
        api(&app, &token, "POST", "/api/v1/scans/device", scan.clone())
            .await
            .0,
        StatusCode::CONFLICT
    );
    api(&app, &token, "POST", "/api/v1/agent/heartbeat", serde_json::json!({"version":"0.1.4", "capabilities":["infrastructure_scan"], "status":"idle"})).await;
    assert_eq!(
        api(&app, &token, "POST", "/api/v1/scans/device", scan.clone())
            .await
            .0,
        StatusCode::ACCEPTED
    );
    let (_, listed) = api(
        &app,
        &token,
        "GET",
        "/api/v1/devices",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(listed[0]["remote_online"], true);
    assert_eq!(listed[0]["zeek_version"], "8.0.4");
    let mut device = state.devices.find_device_by_id(id).await.unwrap().unwrap();
    device
        .capabilities
        .retain(|v| !v.starts_with("remote_heartbeat:"));
    device.capabilities.push(format!(
        "remote_heartbeat:{}",
        (OffsetDateTime::now_utc() - time::Duration::seconds(60))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    ));
    state.devices.save_device(&device).await.unwrap();
    // An ordinary status update cannot revive the worker heartbeat.
    api(
        &app,
        &token,
        "POST",
        "/api/v1/devices/status",
        serde_json::json!({"version":"0.1.4", "zeek_version":"8.0.4"}),
    )
    .await;
    assert_eq!(
        api(&app, &token, "POST", "/api/v1/scans/device", scan)
            .await
            .0,
        StatusCode::CONFLICT
    );
    for path in [
        "/api/v1/assessments/analyze",
        "/api/v1/scans/infrastructure",
        "/api/v1/monitors",
    ] {
        assert_eq!(
            api(&app, &token, "POST", path, serde_json::json!({}))
                .await
                .0,
            StatusCode::CONFLICT
        );
    }
}

#[tokio::test]
async fn synced_capture_is_correlated_reviewed_and_idempotent() {
    let (state, app) = setup_test_app().await;
    let (token, device_id) = create_and_approve_device(&app, "CLI", DEFAULT_ORG_ID).await;
    let observation: mailent_domain::NormalizedObservation = serde_json::from_str(include_str!(
        "../../../fixtures/synthetic/smtp_cert_expired.json"
    ))
    .unwrap();
    let session = mailent_domain::EmailSession::from(&observation);
    let mut assessment = create_sample_infra_assessment(
        "mailent.test",
        60.0,
        "Moderate",
        vec![],
        OffsetDateTime::now_utc(),
    );
    assessment.session_ids = vec![session.session_id];
    assessment.asset_ids.clear();
    let payload = serde_json::json!({"assessment": assessment, "sessions": [session]});
    let (status, response) = api(
        &app,
        &token,
        "POST",
        "/api/v1/assessments/sync",
        payload.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let saved = state
        .assessments
        .find_by_id(assessment.id)
        .await
        .unwrap()
        .unwrap();
    assert!(!saved.asset_ids.is_empty());
    assert!(!saved.finding_ids.is_empty());
    assert!(saved.metadata["ai_provider"].is_string());
    assert_eq!(saved.metadata["source_device_id"], device_id.to_string());
    assert!(!state.investigations.list_all(100).await.unwrap().is_empty());
    assert!(
        state
            .probes
            .list_for_asset(saved.asset_ids[0], 10)
            .await
            .unwrap()
            .is_empty()
    );
    let (_, listed) = api(
        &app,
        &token,
        "GET",
        "/api/v1/devices",
        serde_json::json!({}),
    )
    .await;
    assert!(listed[0]["last_sync_at"].is_string());
    assert_eq!(
        api(&app, &token, "POST", "/api/v1/assessments/sync", payload)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        state
            .assessments
            .find_by_id(assessment.id)
            .await
            .unwrap()
            .unwrap()
            .finding_ids,
        saved.finding_ids
    );
}

#[tokio::test]
async fn remote_scan_expires_before_reconnect_and_revocation_blocks_polling() {
    let (state, app) = setup_test_app().await;
    let (token, id) = create_and_approve_device(&app, "CLI", DEFAULT_ORG_ID).await;
    api(
        &app,
        &token,
        "POST",
        "/api/v1/agent/heartbeat",
        serde_json::json!({"capabilities":["infrastructure_scan"], "status":"idle"}),
    )
    .await;
    let (status, response) = api(
        &app,
        &token,
        "POST",
        "/api/v1/scans/device",
        serde_json::json!({"domain":"mailent.test", "device_id":id}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let job_id = Uuid::parse_str(response["id"].as_str().unwrap()).unwrap();
    let mut job = state.jobs.find_by_id(job_id).await.unwrap().unwrap();
    job.created_at = OffsetDateTime::now_utc() - time::Duration::seconds(61);
    state.jobs.update_job(&job).await.unwrap();
    let (status, polled) = api(
        &app,
        &token,
        "POST",
        "/api/v1/agent/jobs/poll",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{polled}");
    assert!(polled["job"].is_null());
    assert_eq!(
        state.jobs.find_by_id(job_id).await.unwrap().unwrap().state,
        mailent_domain::JobState::Canceled
    );
    state
        .devices
        .revoke_device(id)
        .await
        .unwrap();
    let (status, _) = api(
        &app,
        &token,
        "POST",
        "/api/v1/agent/jobs/poll",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sync_remediation_from_cli_updates_workspace() {
    let (state, app) = setup_test_app().await;
    let (token, _id) = create_and_approve_device(&app, "CLI", DEFAULT_ORG_ID).await;

    let finding_id = Uuid::new_v4();
    let remediation_id = Uuid::new_v4();
    let asset_id = Uuid::new_v4();

    let finding = mailent_domain::Finding {
        id: finding_id,
        rule_id: "TLS_LEGACY_VERSION".into(),
        policy_name: "modern".into(),
        policy_version: "1.1.0".into(),
        reference: "rfc8996".into(),
        severity: mailent_domain::FindingSeverity::Critical,
        category: mailent_domain::FindingCategory::TlsConfiguration,
        title: "Deprecated TLS Version Negotiated".into(),
        description: "Server negotiated TLS 1.0".into(),
        remediation: "Disable TLS 1.0/1.1 in Postfix configuration".into(),
        affected_count: 1,
        first_seen: OffsetDateTime::now_utc(),
        last_seen: OffsetDateTime::now_utc(),
        evidence: vec![],
        organization_id: None,
    };

    let before_session = mailent_domain::EmailSession {
        session_id: Uuid::new_v4(),
        sensor_id: "cli-fix".into(),
        provenance: mailent_domain::ObservationProvenance {
            source: "cli-fix".into(),
            parser: "mailent-probe".into(),
            parser_version: "0.1.4".into(),
        },
        flow: mailent_domain::NetworkFlow {
            src_ip: "127.0.0.1".into(),
            src_port: 0,
            dst_ip: "127.0.0.1".into(),
            dst_port: 25,
        },
        protocol: mailent_domain::EmailProtocol::Smtp,
        starttls_state: Some(mailent_domain::StartTlsState::AdvertisedAndUsed),
        tls_version: Some(mailent_domain::TlsVersion::Tls10),
        cipher_suite: None,
        key_exchange: None,
        certificate: None,
        capture: None,
        first_seen: OffsetDateTime::now_utc(),
        last_seen: OffsetDateTime::now_utc(),
    };

    let guidance = mailent_domain::RemediationGuidance {
        id: Uuid::new_v4(),
        kind: mailent_domain::GuidanceKind::Remediation,
        finding_id: Some(finding_id),
        rule_id: "TLS_LEGACY_VERSION".into(),
        title: "Deprecated TLS Version Negotiated".into(),
        observed: "TLS 1.0 handshake accepted".into(),
        why_it_matters: "Deprecated under RFC 8996".into(),
        recommendation: "smtpd_tls_protocols = >=TLSv1.2".into(),
        recommended_state: "Modern TLS exclusively".into(),
        compatibility_caveats: vec![],
        verification: "Live challenge probes".into(),
        evidence: vec![],
        severity: mailent_domain::FindingSeverity::Critical,
        category: mailent_domain::FindingCategory::TlsConfiguration,
        generated_at: OffsetDateTime::now_utc(),
    };

    let record = mailent_domain::RemediationRecord {
        id: remediation_id,
        asset_id,
        investigation_id: None,
        finding,
        guidance,
        before: before_session,
        condition: mailent_domain::RemediationCondition::LegacyTlsDisabled,
        state: mailent_domain::RemediationState::VerifiedFixed,
        revision: 1,
        started_at: OffsetDateTime::now_utc(),
        applied_at: Some(OffsetDateTime::now_utc()),
        analyst_note: Some("Applied via CLI fix".into()),
        attempts: vec![],
    };

    let payload = serde_json::json!({
        "client_sync_id": Uuid::new_v4(),
        "record": record,
        "probe": null,
        "device_note": "Remediation applied locally to /etc/postfix/main.cf"
    });

    let (status, response) = api(
        &app,
        &token,
        "POST",
        "/api/v1/remediations/sync",
        payload,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "Response: {response}");
    assert_eq!(response["synced"], true);
    assert_eq!(response["remediation_id"], remediation_id.to_string());
    assert_eq!(response["state"], "verified_fixed");

    // Verify persisted in workspace
    let stored = state
        .remediations
        .find_by_id(remediation_id)
        .await
        .unwrap()
        .expect("Remediation record should be persisted");
    assert_eq!(stored.state, mailent_domain::RemediationState::VerifiedFixed);

    let stored_finding = state
        .findings
        .find_by_id(finding_id)
        .await
        .unwrap()
        .expect("Finding should be saved");
    assert_eq!(stored_finding.rule_id, "TLS_LEGACY_VERSION");
}

