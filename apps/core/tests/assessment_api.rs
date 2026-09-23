use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::Engine;
use http_body_util::BodyExt;
use mailent_core::{api::create_router, state::AppState};
use mailent_domain::{AssessmentRecord, AssessmentSummary};
use tower::ServiceExt;

#[tokio::test]
async fn test_assessments_api_lifecycle() {
    let state = AppState::new();
    let app = create_router(state.clone());

    // 1. Initial list should be empty
    let list_req = Request::builder()
        .uri("/api/v1/assessments")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let res = app.clone().oneshot(list_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let list: Vec<AssessmentSummary> = serde_json::from_slice(&body).unwrap();
    assert_eq!(list.len(), 0);

    // 2. Analyze real PCAP: smtp_starttls.pcap
    let analyze_payload = serde_json::json!({
        "pcap_base64": base64::engine::general_purpose::STANDARD.encode(std::fs::read("../../fixtures/pcap/smtp_starttls.pcap").unwrap()),
        "file_name": "smtp_starttls.pcap",
        "title": "Automated STARTTLS Verification"
    });

    let analyze_req = Request::builder()
        .uri("/api/v1/assessments/analyze")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(analyze_payload.to_string()))
        .unwrap();

    let res = app.clone().oneshot(analyze_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let assessment: AssessmentRecord = serde_json::from_slice(&body).unwrap();

    assert_eq!(assessment.title, "Automated STARTTLS Verification");
    assert_eq!(assessment.capture_name, "smtp_starttls.pcap");
    assert!(!assessment.capture_hash.is_empty());
    assert!(
        assessment
            .protocols_identified
            .iter()
            .any(|p| p.contains("SMTP"))
    );
    assert!(!assessment.session_ids.is_empty());
    assert!(!assessment.asset_ids.is_empty());
    assert!(assessment.posture_score >= 80.0);
    assert!(assessment.posture_grade == "A" || assessment.posture_grade == "B");
    assert!(!assessment.ai_risk_classification.is_empty());

    // 3. Fetch assessment by ID
    let get_req = Request::builder()
        .uri(format!("/api/v1/assessments/{}", assessment.id))
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let res = app.clone().oneshot(get_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let fetched: AssessmentRecord = serde_json::from_slice(&body).unwrap();
    assert_eq!(fetched.id, assessment.id);
    assert_eq!(fetched.capture_name, "smtp_starttls.pcap");

    // 4. Analyze legacy PCAP: smtp_legacy.pcap (TLS 1.0, static RSA, expired certificate)
    let legacy_payload = serde_json::json!({
        "pcap_base64": base64::engine::general_purpose::STANDARD.encode(std::fs::read("../../fixtures/pcap/smtp_legacy.pcap").unwrap()),
        "file_name": "smtp_legacy.pcap",
        "title": "Legacy Transport Inspection"
    });

    let legacy_req = Request::builder()
        .uri("/api/v1/assessments/analyze")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(legacy_payload.to_string()))
        .unwrap();

    let res = app.clone().oneshot(legacy_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let legacy_assessment: AssessmentRecord = serde_json::from_slice(&body).unwrap();

    assert_eq!(legacy_assessment.capture_name, "smtp_legacy.pcap");
    assert!(!legacy_assessment.finding_ids.is_empty());
    assert_eq!(legacy_assessment.ai_risk_classification, "CRITICAL");
    assert!(legacy_assessment.posture_score < 70.0);

    // 5. Verify list endpoint now returns 2 sorted assessment summaries
    let list_req_2 = Request::builder()
        .uri("/api/v1/assessments")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let res = app.clone().oneshot(list_req_2).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let summaries: Vec<AssessmentSummary> = serde_json::from_slice(&body).unwrap();
    assert_eq!(summaries.len(), 2);
    assert_eq!(summaries[0].id, legacy_assessment.id);
    assert_eq!(summaries[1].id, assessment.id);
}
