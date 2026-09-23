use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use mailent_core::{api::create_router, state::AppState};
use mailent_domain::NormalizedObservation;
use serde_json::Value;
use tower::ServiceExt;

#[tokio::test]
async fn test_end_to_end_vertical_slice_smtp_legacy_tls10() {
    // 1. Read synthetic fixture from fixtures/synthetic/smtp_tls10_legacy.json
    let fixture_str = include_str!("../../../fixtures/synthetic/smtp_tls10_legacy.json");
    let observation: NormalizedObservation =
        serde_json::from_str(fixture_str).expect("Fixture should parse as NormalizedObservation");

    // 2. Initialize Core router with clean AppState
    let state = AppState::new();
    let app = create_router(state);

    // 3. Send observation to POST /api/v1/observations/evaluate
    let request = Request::builder()
        .uri("/api/v1/observations/evaluate")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(fixture_str))
        .unwrap();

    let response = app
        .oneshot(request)
        .await
        .expect("App should handle request");
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json_res: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    // 4. Verify candidate count and rule findings
    let candidate_count = json_res["candidate_count"]
        .as_u64()
        .expect("candidate_count should be present");
    assert_eq!(
        candidate_count, 2,
        "TLS 1.0 and static RSA should trigger 2 candidate rules"
    );

    let candidates = json_res["candidates"].as_array().expect("candidates array");
    let rule_ids: Vec<&str> = candidates
        .iter()
        .map(|c| c["rule_id"].as_str().unwrap())
        .collect();
    assert!(rule_ids.contains(&"TLS_LEGACY_VERSION"));
    assert!(rule_ids.contains(&"NO_FORWARD_SECRECY"));

    // 5. Verify correlated findings
    let findings = json_res["findings"].as_array().expect("findings array");
    assert_eq!(
        findings.len(),
        2,
        "Should correlate into 2 distinct findings"
    );

    let finding_rules: Vec<&str> = findings
        .iter()
        .map(|f| f["rule_id"].as_str().unwrap())
        .collect();
    assert!(finding_rules.contains(&"TLS_LEGACY_VERSION"));
    assert!(finding_rules.contains(&"NO_FORWARD_SECRECY"));

    // 6. Verify session_id matches observation
    assert_eq!(
        json_res["session_id"].as_str().unwrap(),
        observation.observation_id.to_string()
    );
}

#[tokio::test]
async fn test_health_and_ready_endpoints() {
    let state = AppState::new();
    let app = create_router(state);

    // Health
    let health_req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let health_res = app.clone().oneshot(health_req).await.unwrap();
    assert_eq!(health_res.status(), StatusCode::OK);

    // Ready
    let ready_req = Request::builder()
        .uri("/ready")
        .body(Body::empty())
        .unwrap();
    let ready_res = app.oneshot(ready_req).await.unwrap();
    assert_eq!(ready_res.status(), StatusCode::OK);
}

async fn evaluate_json(app: axum::Router, input: &str) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/observations/evaluate")
                .method("POST")
                .header("Content-Type", "application/json")
                .body(Body::from(input.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn fixtures_have_reproducible_provenance_and_idempotent_storage() {
    let state = AppState::new();
    let app = create_router(state.clone());
    for (input, expected) in [
        (
            include_str!("../../../fixtures/synthetic/smtp_tls10_legacy.json"),
            vec!["NO_FORWARD_SECRECY", "TLS_LEGACY_VERSION"],
        ),
        (
            include_str!("../../../fixtures/synthetic/smtp_tls13_healthy.json"),
            vec![],
        ),
        (
            include_str!("../../../fixtures/synthetic/smtp_cert_expired.json"),
            vec!["CERTIFICATE_EXPIRED"],
        ),
        (
            include_str!("../../../fixtures/synthetic/smtp_static_rsa.json"),
            vec!["NO_FORWARD_SECRECY"],
        ),
    ] {
        let (status, response) = evaluate_json(app.clone(), input).await;
        assert_eq!(status, StatusCode::OK);
        let findings = response["findings"].as_array().unwrap();
        assert_eq!(
            findings
                .iter()
                .map(|f| f["rule_id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            expected
        );
        for f in findings {
            assert_eq!(f["policy_name"], "modern");
            assert_eq!(f["policy_version"], "1.0.0");
            assert!(f["reference"].as_str().unwrap().len() > 3);
            assert_eq!(f["affected_count"], 1);
            assert_eq!(f["evidence"][0]["observation_id"], response["session_id"]);
        }
        let (replay_status, replay) = evaluate_json(app.clone(), input).await;
        assert_eq!(replay_status, StatusCode::OK);
        assert_eq!(response, replay);
    }
    assert_eq!(state.findings.list_all().await.unwrap().len(), 4);
    assert_eq!(state.sessions.list_recent(10).await.unwrap().len(), 4);
}

#[tokio::test]
async fn invalid_conflicting_and_missing_evidence() {
    let state = AppState::new();
    let app = create_router(state.clone());
    let input = include_str!("../../../fixtures/synthetic/smtp_tls10_legacy.json");
    let mut observation: Value = serde_json::from_str(input).unwrap();
    observation["flow"]["dst_ip"] = "not-an-ip".into();
    assert_eq!(
        evaluate_json(app.clone(), &observation.to_string()).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        evaluate_json(app.clone(), "{}").await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        evaluate_json(app.clone(), "{").await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(evaluate_json(app.clone(), input).await.0, StatusCode::OK);
    observation = serde_json::from_str(input).unwrap();
    observation["tls_version"] = "TLSv1.3".into();
    assert_eq!(
        evaluate_json(app.clone(), &observation.to_string()).await.0,
        StatusCode::CONFLICT
    );
    observation["observation_id"] = "b0000000-0000-0000-0000-000000000001".into();
    for key in [
        "tls_version",
        "key_exchange",
        "certificate",
        "starttls_state",
    ] {
        observation[key] = Value::Null;
    }
    let (status, response) = evaluate_json(app, &observation.to_string()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["findings"], serde_json::json!([]));
    assert_eq!(response["observation"]["starttls_state"], Value::Null);
    assert_eq!(
        state.sessions.list_recent(1).await.unwrap()[0].starttls_state,
        None
    );
}

#[tokio::test]
async fn readiness_reports_invalid_policy_as_unavailable() {
    let mut state = AppState::new();
    std::sync::Arc::make_mut(&mut state.policy_pack)
        .rules
        .clear();
    let response = create_router(state)
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn test_submit_observation_json_and_protobuf() {
    let state = AppState::new();
    let app = create_router(state);

    let fixture_str = include_str!("../../../fixtures/synthetic/smtp_tls10_legacy.json");
    let observation: NormalizedObservation =
        serde_json::from_str(fixture_str).expect("Valid fixture");

    // 1. Submit JSON
    let req = Request::builder()
        .uri("/api/v1/observations")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(fixture_str))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["session_id"], observation.observation_id.to_string());
    assert_eq!(json["findings_count"], 2);

    // 2. Replay JSON is idempotent
    let replay_req = Request::builder()
        .uri("/api/v1/observations")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(fixture_str))
        .unwrap();
    let replay_res = app.clone().oneshot(replay_req).await.unwrap();
    assert_eq!(replay_res.status(), StatusCode::OK);

    // 3. Conflicting submission returns 409
    let mut conflict: Value = serde_json::from_str(fixture_str).unwrap();
    conflict["flow"]["dst_port"] = 2525.into();
    let conflict_req = Request::builder()
        .uri("/api/v1/observations")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(conflict.to_string()))
        .unwrap();
    let conflict_res = app.clone().oneshot(conflict_req).await.unwrap();
    assert_eq!(conflict_res.status(), StatusCode::CONFLICT);

    // 4. Submit Protobuf
    let modern_str = include_str!("../../../fixtures/synthetic/smtp_tls13_healthy.json");
    let modern_obs: NormalizedObservation = serde_json::from_str(modern_str).unwrap();
    let proto_bytes = mailent_events::wire::encode(&modern_obs).unwrap();

    let proto_req = Request::builder()
        .uri("/api/v1/observations")
        .method("POST")
        .header("Content-Type", "application/x-protobuf")
        .body(Body::from(proto_bytes))
        .unwrap();
    let proto_res = app.oneshot(proto_req).await.unwrap();
    assert_eq!(proto_res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_sessions_and_findings_query_endpoints() {
    let state = AppState::new();
    let app = create_router(state);

    let fixture_str = include_str!("../../../fixtures/synthetic/smtp_tls10_legacy.json");
    let req = Request::builder()
        .uri("/api/v1/observations")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(fixture_str))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );

    // GET /api/v1/sessions
    let sess_req = Request::builder()
        .uri("/api/v1/sessions")
        .body(Body::empty())
        .unwrap();
    let sess_res = app.clone().oneshot(sess_req).await.unwrap();
    assert_eq!(sess_res.status(), StatusCode::OK);
    let sess_body = sess_res.into_body().collect().await.unwrap().to_bytes();
    let sessions: Vec<Value> = serde_json::from_slice(&sess_body).unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0]["protocol"], "SMTP");
    assert_eq!(sessions[0]["findings_count"], 2);
    assert_eq!(sessions[0]["forward_secrecy"], "not_supported");

    let session_id = sessions[0]["session_id"].as_str().unwrap();

    // GET /api/v1/sessions/{id}
    let detail_req = Request::builder()
        .uri(format!("/api/v1/sessions/{session_id}"))
        .body(Body::empty())
        .unwrap();
    let detail_res = app.clone().oneshot(detail_req).await.unwrap();
    assert_eq!(detail_res.status(), StatusCode::OK);
    let detail_body = detail_res.into_body().collect().await.unwrap().to_bytes();
    let detail: Value = serde_json::from_slice(&detail_body).unwrap();
    assert_eq!(detail["session"]["session_id"], session_id);
    assert_eq!(detail["findings"].as_array().unwrap().len(), 2);

    // GET /api/v1/findings
    let find_req = Request::builder()
        .uri("/api/v1/findings")
        .body(Body::empty())
        .unwrap();
    let find_res = app.clone().oneshot(find_req).await.unwrap();
    assert_eq!(find_res.status(), StatusCode::OK);
    let find_body = find_res.into_body().collect().await.unwrap().to_bytes();
    let findings: Vec<Value> = serde_json::from_slice(&find_body).unwrap();
    assert_eq!(findings.len(), 2);

    // GET /api/v1/findings?session_id=...
    let filter_req = Request::builder()
        .uri(format!("/api/v1/findings?session_id={session_id}"))
        .body(Body::empty())
        .unwrap();
    let filter_res = app.clone().oneshot(filter_req).await.unwrap();
    assert_eq!(filter_res.status(), StatusCode::OK);
    let filter_body = filter_res.into_body().collect().await.unwrap().to_bytes();
    let filtered_findings: Vec<Value> = serde_json::from_slice(&filter_body).unwrap();
    assert_eq!(filtered_findings.len(), 2);

    // GET /api/v1/findings/{id}
    let finding_id = findings[0]["id"].as_str().unwrap();
    let single_req = Request::builder()
        .uri(format!("/api/v1/findings/{finding_id}"))
        .body(Body::empty())
        .unwrap();
    let single_res = app.clone().oneshot(single_req).await.unwrap();
    assert_eq!(single_res.status(), StatusCode::OK);

    // Nonexistent finding returns 404
    let not_found_req = Request::builder()
        .uri(format!("/api/v1/findings/{}", uuid::Uuid::new_v4()))
        .body(Body::empty())
        .unwrap();
    let not_found_res = app.oneshot(not_found_req).await.unwrap();
    assert_eq!(not_found_res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_full_pcap_to_core_pipeline() {
    let zeek_bin = if std::path::Path::new("scripts/zeek-container").exists() {
        std::path::PathBuf::from("scripts/zeek-container")
    } else {
        std::path::PathBuf::from("zeek")
    };

    let pcap_path = std::path::Path::new("fixtures/pcap/smtp_starttls.pcap");
    if !pcap_path.exists() {
        return;
    }

    let analysis = mailent_sensor::analyze::analyze(pcap_path, &zeek_bin, "sensor-test-01", true)
        .await
        .expect("PCAP analysis should succeed");

    assert_eq!(analysis.observations.len(), 1);
    let observation = &analysis.observations[0];
    assert_eq!(observation.protocol, mailent_domain::EmailProtocol::Smtp);
    assert_eq!(
        observation.starttls_state,
        Some(mailent_domain::StartTlsState::TlsEstablished)
    );
    assert_eq!(
        observation.tls_version,
        Some(mailent_domain::TlsVersion::Tls12)
    );
    assert_eq!(
        observation.key_exchange,
        Some(mailent_domain::KeyExchange::Ecdhe)
    );

    let capture = observation
        .capture
        .as_ref()
        .expect("Capture evidence present");
    assert!(!capture.timeline.is_empty());
    let kinds: Vec<&str> = capture.timeline.iter().map(|e| e.kind.as_str()).collect();
    assert!(kinds.contains(&"tcp_connected"));
    assert!(kinds.contains(&"smtp_greeting"));
    assert!(kinds.contains(&"ehlo"));
    assert!(kinds.contains(&"starttls_advertised"));
    assert!(kinds.contains(&"starttls_requested"));
    assert!(kinds.contains(&"starttls_accepted"));
    assert!(kinds.contains(&"tls_client_hello"));
    assert!(kinds.contains(&"tls_server_hello"));
    assert!(kinds.contains(&"certificate_observed"));
    assert!(kinds.contains(&"key_exchange_ecdhe"));
    assert!(kinds.contains(&"tls_established"));

    // Now pipe into Core
    let state = AppState::new();
    let app = create_router(state);

    let proto_bytes = mailent_events::wire::encode(observation).unwrap();
    let submit_req = Request::builder()
        .uri("/api/v1/observations")
        .method("POST")
        .header("Content-Type", "application/x-protobuf")
        .body(Body::from(proto_bytes))
        .unwrap();

    let submit_res = app.clone().oneshot(submit_req).await.unwrap();
    assert_eq!(submit_res.status(), StatusCode::OK);

    // Query session detail
    let session_id = observation.observation_id.to_string();
    let get_req = Request::builder()
        .uri(format!("/api/v1/sessions/{session_id}"))
        .body(Body::empty())
        .unwrap();
    let get_res = app.oneshot(get_req).await.unwrap();
    assert_eq!(get_res.status(), StatusCode::OK);

    let get_body = get_res.into_body().collect().await.unwrap().to_bytes();
    let detail: Value = serde_json::from_slice(&get_body).unwrap();
    assert_eq!(detail["session"]["protocol"], "smtp");
    assert_eq!(detail["session"]["starttls_state"], "tls_established");
    assert_eq!(detail["forward_secrecy"], "supported");
    assert_eq!(detail["certificate_state"], "expired");
    let findings = detail["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["rule_id"], "CERTIFICATE_EXPIRED");
}
