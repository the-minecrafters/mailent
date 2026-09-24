use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use mailent_core::{api::create_router, state::AppState};
use serde_json::Value;
use tower::ServiceExt;

const LEGACY: &str = include_str!("../../../fixtures/synthetic/smtp_tls10_legacy.json");

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

async fn get_bytes(
    app: &axum::Router,
    uri: &str,
) -> (StatusCode, Option<axum::http::HeaderValue>, Vec<u8>) {
    let res = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let content_type = res.headers().get("content-type").cloned();
    let body = res.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, content_type, body)
}

#[tokio::test]
async fn asset_report_json_is_deterministic_and_complete() {
    let state = AppState::new();
    let app = create_router(state.clone());

    let (status, submitted) = post_observation(&app, LEGACY).await;
    assert_eq!(status, StatusCode::OK);
    let asset_id = submitted["asset_id"].as_str().unwrap();

    let (status, ct, body) = get_bytes(&app, &format!("/api/v1/assets/{asset_id}/report")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        ct.as_ref()
            .map(|v| v.to_str().unwrap())
            .unwrap()
            .starts_with("application/json")
    );
    let report: Value = serde_json::from_slice(&body).unwrap();

    // Case metadata: deterministic report id, reproducible generator info.
    assert!(report["metadata"]["report_id"].is_string());
    assert_eq!(report["metadata"]["policy_name"], "modern");
    assert_eq!(
        report["metadata"]["policy_version"],
        mailent_policy::PolicyPack::modern().version
    );

    // Reconstructed session with transport details.
    let sessions = report["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0]["protocol"], "SMTP");
    assert_eq!(sessions[0]["tls_version"], "TLSv1.0");
    assert_eq!(sessions[0]["key_exchange"], "\"rsa_static\"");

    // Certificate identity surfaced; extended crypto details honestly absent
    // (passive capture path cannot extract PKI internals).
    let certs = report["certificates"].as_array().unwrap();
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0]["subject"], "CN=mail.legacy-gateway.example");
    assert!(certs[0]["crypto_details"].is_null());
    let gaps = report["evidence_gaps"].as_array().unwrap();
    assert!(
        gaps.iter().any(|g| g
            .as_str()
            .unwrap()
            .contains("Cryptographic certificate details")),
        "missing-crypto gap must be stated, got {gaps:?}"
    );

    // Policy findings present with deterministic provenance.
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2);
    for f in findings {
        assert_eq!(f["provenance"], "deterministic_finding");
    }

    // Posture + risk prioritization included.
    assert!(report["posture"].is_object());
    assert_eq!(report["posture"]["grade"], "critical");
    assert!(
        report["risk"]["prioritized_actions"]
            .as_array()
            .unwrap()
            .len()
            >= 2
    );

    // Remediation guidance separated from best practices.
    assert!(!report["remediation"].as_array().unwrap().is_empty());

    // Same evidence → same report content (fingerprint equality).
    let (_, _, body2) = get_bytes(&app, &format!("/api/v1/assets/{asset_id}/report")).await;
    let report2: Value = serde_json::from_slice(&body2).unwrap();
    // report_id is content-derived; generated_at may differ.
    assert_eq!(
        report["metadata"]["report_id"],
        report2["metadata"]["report_id"]
    );
    assert_eq!(
        report["posture"]["id"], report2["posture"]["id"],
        "posture identity must be stable across regenerations"
    );
}

#[tokio::test]
async fn report_formats_carry_equivalent_core_findings() {
    let state = AppState::new();
    let app = create_router(state.clone());

    let (status, submitted) = post_observation(&app, LEGACY).await;
    assert_eq!(status, StatusCode::OK);
    let asset_id = submitted["asset_id"].as_str().unwrap();

    // JSON
    let (s1, _, json_body) = get_bytes(
        &app,
        &format!("/api/v1/assets/{asset_id}/report?format=json"),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);
    // HTML
    let (s2, ct2, html_body) = get_bytes(
        &app,
        &format!("/api/v1/assets/{asset_id}/report?format=html"),
    )
    .await;
    assert_eq!(s2, StatusCode::OK);
    assert!(
        ct2.as_ref()
            .map(|v| v.to_str().unwrap())
            .unwrap()
            .starts_with("text/html")
    );
    // PDF
    let (s3, ct3, pdf_body) = get_bytes(
        &app,
        &format!("/api/v1/assets/{asset_id}/report?format=pdf"),
    )
    .await;
    assert_eq!(s3, StatusCode::OK);
    assert!(
        ct3.as_ref()
            .map(|v| v.to_str().unwrap())
            .unwrap()
            .starts_with("application/pdf")
    );

    let json = String::from_utf8_lossy(&json_body);
    let html = String::from_utf8_lossy(&html_body);
    let pdf = String::from_utf8_lossy(&pdf_body);

    // Equivalent core content across formats: rule IDs, TLS version, cert subject.
    for needle in [
        "TLS_LEGACY_VERSION",
        "TLSv1.0",
        "mail.legacy-gateway.example",
    ] {
        assert!(json.contains(needle), "json missing {needle}");
        assert!(html.contains(needle), "html missing {needle}");
        assert!(pdf.contains(needle), "pdf missing {needle}");
    }

    assert!(pdf_body.starts_with(b"%PDF-1.4"));
    assert!(html.starts_with("<!DOCTYPE html>"));

    // Provenance distinction is visible in human formats.
    assert!(html.contains("policy finding"));
    assert!(html.contains("observed fact"));
    assert!(pdf.contains("policy finding"));
}

#[tokio::test]
async fn investigation_report_includes_ai_context_when_present() {
    let state = AppState::new();
    let app = create_router(state.clone());

    let (status, submitted) = post_observation(&app, LEGACY).await;
    assert_eq!(status, StatusCode::OK);
    let asset_id = submitted["asset_id"].as_str().unwrap();

    let (status, investigations) = get_json_list(&app, "/api/v1/investigations?limit=50").await;
    assert_eq!(status, StatusCode::OK);
    let inv = investigations
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["asset_id"] == asset_id)
        .expect("investigation exists")
        .clone();
    let inv_id = inv["id"].as_str().unwrap();

    let (status, _, body) = get_bytes(
        &app,
        &format!("/api/v1/investigations/{inv_id}/report?format=json"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let report: Value = serde_json::from_slice(&body).unwrap();

    // Investigation context linked.
    assert_eq!(report["metadata"]["investigation_id"], inv["id"]);
    // Active verification section present even when empty (honest: no probes ran).
    assert!(
        report["active_verifications"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // Jev ran with deterministic fallback in tests → AI assessment is present
    // only if a decision was recorded; either way, when present it is labelled.
    if !report["ai_assessment"].is_null() {
        assert!(
            report["ai_assessment"]["caveat"]
                .as_str()
                .unwrap()
                .contains("Supplemental AI output")
        );
        assert!(report["ai_assessment"]["provenance"] == "ai_assessment");
    }
}

async fn get_json_list(app: &axum::Router, uri: &str) -> (StatusCode, Value) {
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
async fn no_private_content_leaks_into_reports() {
    let state = AppState::new();
    let app = create_router(state.clone());
    let (status, _) = post_observation(&app, LEGACY).await;
    assert_eq!(status, StatusCode::OK);
    // Reports derive only from transport evidence; verify no credential or
    // mail-content markers exist in any format.
    for format in ["json", "html", "pdf"] {
        let asset_id = state.assets.list_all().await.unwrap()[0].id;
        let (_, _, body) = get_bytes(
            &app,
            &format!("/api/v1/assets/{asset_id}/report?format={format}"),
        )
        .await;
        let text = String::from_utf8_lossy(&body).to_lowercase();
        for marker in [
            "password",
            "auth plain",
            "auth login",
            "message-id",
            "subject:",
        ] {
            assert!(!text.contains(marker), "{format} leaked {marker}");
        }
    }
}

#[tokio::test]
async fn report_for_unknown_asset_returns_404() {
    let state = AppState::new();
    let app = create_router(state);
    let (status, _, _) = get_bytes(
        &app,
        "/api/v1/assets/00000000-0000-0000-0000-00000000dead/report",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
