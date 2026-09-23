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

#[tokio::test]
async fn test_assessments_api_edge_cases_and_adversarial_inputs() {
    let state = AppState::new();
    let app = create_router(state);

    // 1. Missing pcap_base64 field
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/assessments/analyze")
                .method("POST")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"file_name":"test.pcap"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // 2. Corrupted base64
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/assessments/analyze")
                .method("POST")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"pcap_base64":"!not-valid-base64==="}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // 3. Truncated capture (< 24 bytes)
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/assessments/analyze")
                .method("POST")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::json!({
                    "pcap_base64": base64::engine::general_purpose::STANDARD.encode(b"too small"),
                    "file_name": "too_small.pcap"
                }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // 4. Invalid magic header (24 bytes but not PCAP magic)
    let fake_bytes = vec![0x42u8; 32];
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/assessments/analyze")
                .method("POST")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::json!({
                    "pcap_base64": base64::engine::general_purpose::STANDARD.encode(&fake_bytes),
                    "file_name": "fake.pcap"
                }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // 5. Empty valid PCAP (24 bytes) -> UNPROCESSABLE_ENTITY (no email connections)
    let empty_pcap = std::fs::read("../../fixtures/pcap/empty.pcap").unwrap();
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/assessments/analyze")
                .method("POST")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::json!({
                    "pcap_base64": base64::engine::general_purpose::STANDARD.encode(&empty_pcap),
                    "file_name": "empty.pcap"
                }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // 6. Downgrade PCAP -> CREATED, finding STARTTLS_MISSING detected
    let downgrade_path =
        std::path::Path::new("../../fixtures/pcap_edge/smtp_downgrade_auth_exposed.pcap");
    if downgrade_path.exists() {
        let downgrade_bytes = std::fs::read(downgrade_path).unwrap();
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/assessments/analyze")
                    .method("POST")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::json!({
                        "pcap_base64": base64::engine::general_purpose::STANDARD.encode(&downgrade_bytes),
                        "file_name": "smtp_downgrade.pcap"
                    }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let assessment: AssessmentRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(assessment.finding_ids.len(), 1);
        assert_eq!(assessment.posture_grade, "B");
        assert_eq!(assessment.posture_score, 85.0);
    }

    // 7. IMAPS TLS 1.3 PCAP -> CREATED, IMAPS identified
    let imap_path = std::path::Path::new("../../fixtures/pcap/imap_tls13.pcap");
    if imap_path.exists() {
        let imap_bytes = std::fs::read(imap_path).unwrap();
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/assessments/analyze")
                    .method("POST")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::json!({
                        "pcap_base64": base64::engine::general_purpose::STANDARD.encode(&imap_bytes),
                        "file_name": "imap_tls13.pcap"
                    }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let assessment: AssessmentRecord = serde_json::from_slice(&body).unwrap();
        assert!(
            assessment
                .protocols_identified
                .iter()
                .any(|p| p.contains("IMAPS"))
        );
    }

    // 8. IPv6 SMTP PCAP -> CREATED, SMTP identified
    let ipv6_path = std::path::Path::new("../../fixtures/pcap_edge/ipv6_smtp.pcap");
    if ipv6_path.exists() {
        let ipv6_bytes = std::fs::read(ipv6_path).unwrap();
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/assessments/analyze")
                    .method("POST")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::json!({
                        "pcap_base64": base64::engine::general_purpose::STANDARD.encode(&ipv6_bytes),
                        "file_name": "ipv6_smtp.pcap"
                    }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let assessment: AssessmentRecord = serde_json::from_slice(&body).unwrap();
        assert!(
            assessment
                .protocols_identified
                .iter()
                .any(|p| p.contains("SMTP"))
        );
    }

    // 9. Non-mail HTTP on port 25 -> UNPROCESSABLE_ENTITY
    let http_path = std::path::Path::new("../../fixtures/pcap_edge/non_mail_http_on_port_25.pcap");
    if http_path.exists() {
        let http_bytes = std::fs::read(http_path).unwrap();
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/assessments/analyze")
                    .method("POST")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::json!({
                        "pcap_base64": base64::engine::general_purpose::STANDARD.encode(&http_bytes),
                        "file_name": "non_mail_http.pcap"
                    }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    // 10. Corrupted packet length -> INTERNAL_SERVER_ERROR
    let corrupt_path = std::path::Path::new("../../fixtures/pcap_edge/corrupted_packet_len.pcap");
    if corrupt_path.exists() {
        let corrupt_bytes = std::fs::read(corrupt_path).unwrap();
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/assessments/analyze")
                    .method("POST")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::json!({
                        "pcap_base64": base64::engine::general_purpose::STANDARD.encode(&corrupt_bytes),
                        "file_name": "corrupt.pcap"
                    }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }
}
