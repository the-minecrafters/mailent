use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use mailent_core::{api::create_router, state::AppState};
use mailent_domain::{AssessmentRecord, AssessmentSummary, CaptureMetadata};
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
async fn workspace_acquisition_endpoints_explain_local_cli_workflows() {
    let state = AppState::new();
    let app = create_router(state.clone());
    for endpoint in [
        "/api/v1/assessments/analyze",
        "/api/v1/scans/infrastructure",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(endpoint)
                    .method("POST")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"pcap_base64":"unused","domain":"example.com"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["code"], "cli_required");
        assert_eq!(body["setup_url"], "/workspace/installations");
        let commands = body["commands"].as_array().unwrap();
        assert!(
            commands
                .iter()
                .any(|command| command == "mailent analyze <capture.pcap> --sync")
        );
        assert!(
            commands
                .iter()
                .any(|command| command == "mailent scan <domain> --sync")
        );
    }
    assert!(state.assessments.list_all().await.unwrap().is_empty());
}

#[tokio::test]
async fn workspace_lists_and_exports_stored_cli_assessments() {
    let state = AppState::new();
    let now = OffsetDateTime::now_utc();
    let assessment = AssessmentRecord::new_capture(
        Uuid::new_v4(),
        "Captured SMTP traffic".into(),
        CaptureMetadata {
            capture_name: "smtp_starttls.pcap".into(),
            capture_hash: "ab".repeat(32),
            capture_size_bytes: 4096,
            time_range_start: Some(now),
            time_range_end: Some(now),
        },
        now,
        vec!["SMTP".into()],
        vec![],
        vec![],
        vec![],
        vec![],
        100.0,
        "Strong".into(),
        vec![],
        "LOW".into(),
        "No findings in this stored result.".into(),
        0.0,
        serde_json::json!({"source": "mailent-cli"}),
    );
    state.assessments.save(&assessment).await.unwrap();
    let app = create_router(state);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/assessments")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let summaries: Vec<AssessmentSummary> =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].id, assessment.id);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/assessments/{}", assessment.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let fetched: AssessmentRecord =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(fetched.capture_hash, assessment.capture_hash);
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/assessments/{}/report?format=json",
                    assessment.id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let report: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(report.is_object());
}
