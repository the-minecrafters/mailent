#[path = "../../../tests/support/databases.rs"]
mod databases;
use axum::http::StatusCode;
use mailent_core::{api::create_router, config::CoreConfig, state::AppState};
use serde_json::Value;
use tower::ServiceExt;

async fn post_json(app: axum::Router, uri: &str, body: &str) -> (StatusCode, Value) {
    use tower::ServiceExt;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

async fn get_json(app: axum::Router, uri: &str) -> (StatusCode, Value) {
    use tower::ServiceExt;
    let request = axum::http::Request::builder()
        .method("GET")
        .uri(uri)
        .body(axum::body::Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

#[tokio::test]
async fn test_core_persistence_restart_and_drift() {
    let Some(db) = databases::TestDatabases::start().await else {
        return;
    };
    let config = CoreConfig {
        database_url: Some(db.postgres_url.clone()),
        clickhouse_url: Some(db.clickhouse_url.clone()),
        clickhouse_database: db.clickhouse_database.clone(),
        ..Default::default()
    };

    // 1. First Core lifetime
    let state = AppState::from_config(&config)
        .await
        .expect("isolated databases");
    let app = create_router(state.clone());

    let fixture = include_str!("../../../fixtures/synthetic/smtp_tls10_legacy.json");
    let (status, res) = post_json(app.clone(), "/api/v1/observations", fixture).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "First observation ingestion failed: {res}"
    );
    let session_id = res["session_id"].as_str().unwrap().to_string();
    let asset_id = res["asset_id"].as_str().unwrap().to_string();

    // Verify session in ClickHouse
    let (status, sessions) = get_json(app.clone(), "/api/v1/sessions").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        sessions
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["session_id"] == session_id)
    );

    // Verify asset in PostgreSQL
    let (status, asset) = get_json(app.clone(), &format!("/api/v1/assets/{asset_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(asset["id"], asset_id);

    // Re-ingest same observation (replay safety)
    let (status, replay_res) = post_json(app.clone(), "/api/v1/observations", fixture).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay_res["session_id"], session_id);

    // 2. SIMULATE CORE RESTART: re-initialize AppState from same config
    drop(app);
    drop(state);

    let restarted_state = AppState::from_config(&config)
        .await
        .expect("reconnect after restart");
    let restarted_app = create_router(restarted_state);

    // Verify that data survived Core restart!
    let (status, restarted_sessions) = get_json(restarted_app.clone(), "/api/v1/sessions").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        restarted_sessions
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["session_id"] == session_id)
    );

    let (status, restarted_asset) =
        get_json(restarted_app.clone(), &format!("/api/v1/assets/{asset_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(restarted_asset["id"], asset_id);

    // 3. Test Configuration Drift Detection:
    // Send a new observation for the same server IP (dst_ip), but negotiating TLS 1.3 with a new cipher suite
    let mut drift_obs: Value = serde_json::from_str(fixture).unwrap();
    drift_obs["observation_id"] = Value::String(uuid::Uuid::new_v4().to_string());
    drift_obs["tls_version"] = Value::String("TLSv1.3".to_string());
    drift_obs["cipher_suite"] = serde_json::json!({
        "id": 4865,
        "name": "TLS_AES_128_GCM_SHA256"
    });
    drift_obs["key_exchange"] = Value::String("ecdhe".to_string());

    let (status, drift_res) = post_json(
        restarted_app.clone(),
        "/api/v1/observations",
        &drift_obs.to_string(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Drift observation ingestion failed: {drift_res}"
    );

    // Verify drift event was generated for this asset
    let (status, drift_events) = get_json(
        restarted_app.clone(),
        &format!("/api/v1/assets/{asset_id}/drift"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let events = drift_events.as_array().unwrap();
    assert!(
        !events.is_empty(),
        "Expected drift events to be recorded for asset"
    );
    assert!(
        events
            .iter()
            .any(|e| e["kind"] == "NewTlsVersion" || e["kind"] == "NewCipherSuite")
    );

    // 4. Training records are captured at decision time and survive a restart.
    let (status, training) = get_json(
        restarted_app.clone(),
        &format!("/api/v1/training?asset_id={asset_id}&limit=10"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "training list endpoint");
    let records = training.as_array().unwrap();
    assert!(
        !records.is_empty(),
        "expected at least one captured training record"
    );
    for rec in records {
        assert_eq!(rec["asset_id"], asset_id);
        assert_eq!(rec["feature_schema_version"], 1);
        assert!(
            rec["features"].is_object(),
            "features snapshot is structured"
        );
    }

    // Analyst label can be attached to a persisted record.
    let record_id = records[0]["id"].as_str().unwrap();
    let (status, labeled) = post_json(
        restarted_app.clone(),
        &format!("/api/v1/training/{record_id}/label"),
        r#"{"outcome":"analyst_reviewed","label_source":"analyst","note":"restart persistence check"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "analyst label endpoint: {labeled}");
    assert_eq!(labeled["analyst_label"]["outcome"], "analyst_reviewed");

    // JSONL export path is reachable.
    let status_response = restarted_app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/api/v1/training/export")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status_response.status(), StatusCode::OK);
    drop(restarted_app);
    db.finish().await;
}
