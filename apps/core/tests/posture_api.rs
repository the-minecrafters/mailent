use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use mailent_core::{api::create_router, state::AppState};
use serde_json::Value;
use tower::ServiceExt;

const LEGACY: &str = include_str!("../../../fixtures/synthetic/smtp_tls10_legacy.json");
const MODERN: &str = include_str!("../../../fixtures/synthetic/smtp_tls13_healthy.json");

async fn post_observation(app: &axum::Router, fixture: &str) -> (StatusCode, Value) {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/observations")
                .method("POST")
                .header("Content-Type", "application/json")
                .body(Body::from(fixture.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

async fn get_json(app: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let res = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

#[tokio::test]
async fn asset_posture_is_deterministic_and_capped_for_legacy_tls() {
    let state = AppState::new();
    let app = create_router(state.clone());

    let (status, submitted) = post_observation(&app, LEGACY).await;
    assert_eq!(status, StatusCode::OK);
    let asset_id = submitted["asset_id"].as_str().unwrap();

    let (status, first) = get_json(&app, &format!("/api/v1/assets/{asset_id}/posture")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["posture"]["score_version"], "1.0.0");

    // Deterministic + reproducible: identical evidence → identical score and ID.
    let (_, second) = get_json(&app, &format!("/api/v1/assets/{asset_id}/posture")).await;
    assert_eq!(first["posture"]["score"], second["posture"]["score"]);
    assert_eq!(first["posture"]["id"], second["posture"]["id"]);

    // Serious findings must visibly affect posture: critical TLS 1.0 finding caps
    // the composite score far below what a plain average would produce.
    let score = first["posture"]["score"].as_f64().unwrap();
    assert!(
        score <= 25.0,
        "critical finding must cap score, got {score}"
    );
    assert_eq!(first["posture"]["score_capped"], true);
    assert_eq!(first["posture"]["grade"], "critical");
    assert!(
        first["posture"]["worst_findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w == "TLS_LEGACY_VERSION")
    );

    // Category breakdowns exist and deductions trace back to the finding.
    let categories = first["posture"]["categories"].as_array().unwrap();
    assert_eq!(categories.len(), 4);
    let transport = categories
        .iter()
        .find(|c| c["category"] == "transport_security")
        .unwrap();
    assert!(
        transport["finding_rule_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "TLS_LEGACY_VERSION")
    );
    assert_eq!(first["posture"]["deductions"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn healthy_asset_scores_high_without_cap() {
    let state = AppState::new();
    let app = create_router(state.clone());

    let (status, submitted) = post_observation(&app, MODERN).await;
    assert_eq!(status, StatusCode::OK);
    let asset_id = submitted["asset_id"].as_str().unwrap();

    let (status, posture) = get_json(&app, &format!("/api/v1/assets/{asset_id}/posture")).await;
    assert_eq!(status, StatusCode::OK);
    let score = posture["posture"]["score"].as_f64().unwrap();
    assert!(
        score >= 90.0,
        "healthy TLS 1.3 asset should score high, got {score}"
    );
    assert_eq!(posture["posture"]["score_capped"], false);
    assert_eq!(posture["posture"]["grade"], "strong");
    // Best-practice guidance present, remediation absent (no findings).
    let guidance = posture["guidance"].as_array().unwrap();
    assert!(
        guidance.iter().all(|g| g["kind"] == "best_practice"),
        "no findings → only best-practice guidance"
    );
}

#[tokio::test]
async fn remediation_maps_to_finding_and_includes_verification() {
    let state = AppState::new();
    let app = create_router(state.clone());

    let (status, submitted) = post_observation(&app, LEGACY).await;
    assert_eq!(status, StatusCode::OK);
    let asset_id = submitted["asset_id"].as_str().unwrap();

    let (_, posture) = get_json(&app, &format!("/api/v1/assets/{asset_id}/posture")).await;
    let guidance = posture["guidance"].as_array().unwrap();
    let remediations: Vec<&Value> = guidance
        .iter()
        .filter(|g| g["kind"] == "remediation")
        .collect();
    assert_eq!(remediations.len(), 2, "one remediation per finding");

    let tls = remediations
        .iter()
        .find(|g| g["rule_id"] == "TLS_LEGACY_VERSION")
        .expect("remediation for TLS_LEGACY_VERSION");
    assert!(tls["observed"].as_str().unwrap().contains("TLS"));
    assert!(
        tls["recommendation"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("disable")
    );
    assert!(
        tls["verification"]
            .as_str()
            .unwrap()
            .contains("active Mailent probe"),
        "active verification must be suggested after remediation"
    );
    assert!(tls["finding_id"].is_string(), "maps to the finding");
}

#[tokio::test]
async fn session_posture_reflects_session_findings() {
    let state = AppState::new();
    let app = create_router(state.clone());

    let (status, submitted) = post_observation(&app, LEGACY).await;
    assert_eq!(status, StatusCode::OK);
    let session_id = submitted["session_id"].as_str().unwrap();

    let (status, posture) = get_json(&app, &format!("/api/v1/sessions/{session_id}/posture")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(posture["posture"]["subject_kind"], "session");
    let score = posture["posture"]["score"].as_f64().unwrap();
    assert!(score <= 25.0, "session with critical finding must cap");

    let (status, _) = get_json(
        &app,
        "/api/v1/sessions/00000000-0000-0000-0000-00000000dead/posture",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn investigation_posture_endpoint_resolves() {
    let state = AppState::new();
    let app = create_router(state.clone());

    let (status, submitted) = post_observation(&app, LEGACY).await;
    assert_eq!(status, StatusCode::OK);
    let asset_id = submitted["asset_id"].as_str().unwrap();

    let (status, investigations) = get_json(&app, "/api/v1/investigations?limit=50").await;
    assert_eq!(status, StatusCode::OK);
    let inv = investigations
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["asset_id"] == asset_id)
        .expect("investigation correlated for legacy observation");
    let inv_id = inv["id"].as_str().unwrap();

    let (status, posture) =
        get_json(&app, &format!("/api/v1/investigations/{inv_id}/posture")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(posture["posture"]["subject_kind"], "investigation");
}

#[tokio::test]
async fn unknown_assets_return_404() {
    let state = AppState::new();
    let app = create_router(state);
    let (status, _) = get_json(
        &app,
        "/api/v1/assets/00000000-0000-0000-0000-00000000dead/posture",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
