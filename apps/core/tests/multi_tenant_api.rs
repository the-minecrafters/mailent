use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use mailent_core::{AppState, api::create_router, auth::protect};
use mailent_domain::{AssessmentRecord, CaptureMetadata, DEFAULT_ORG_ID, Device};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
async fn test_device_challenge_approval_and_revocation_flow() {
    let state = AppState::new();
    let app = protect(create_router(state.clone()), None, state.clone());

    // 1. Create Challenge
    let req_body = serde_json::json!({
        "device_name": "Test CLI Laptop",
        "hostname": "test-box",
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

    assert_eq!(res.status(), StatusCode::CREATED);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let challenge_res: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let code = challenge_res["code"].as_str().unwrap();
    assert!(code.starts_with("MLT-"));

    // 2. Poll Challenge (should be pending)
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

    assert_eq!(res.status(), StatusCode::ACCEPTED);

    // 3. Inspect Challenge info
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/devices/authorize/{code}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    // 4. Approve Challenge (as authenticated user/local user)
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/devices/authorize/{code}/approve"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let approve_res: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(approve_res["status"], "approved");

    // 5. Poll Challenge again (should be approved with token)
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

    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let poll_res: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(poll_res["status"], "approved");
    let token = poll_res["token"].as_str().unwrap();
    assert!(token.starts_with("mlt_"));

    // 6. Access device status using Bearer token
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/devices/status")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let status_res: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status_res["authenticated"], true);
    assert_eq!(status_res["type"], "device");
    assert_eq!(status_res["name"], "Test CLI Laptop");

    // 7. Log out (revokes device token)
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/devices/logout")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    // 8. Device token should now be rejected as revoked (401)
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/devices/status")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_multi_tenant_isolation_assessments_and_devices() {
    let state = AppState::new();
    let app = protect(create_router(state.clone()), None, state.clone());

    // Setup Org A and Org B
    let org_a = DEFAULT_ORG_ID;
    let org_b = Uuid::new_v4();

    state
        .organizations
        .save(&mailent_domain::Organization {
            id: org_b,
            name: "Globex Corp".into(),
            slug: "globex-corp".into(),
            created_at: OffsetDateTime::now_utc(),
        })
        .await
        .unwrap();

    // Create Device A for Org A
    let device_a_id = Uuid::new_v4();
    let token_a = "mlt_token_for_org_a_device_123456";
    let token_a_hash = format!("{:x}", Sha256::digest(token_a.as_bytes()));
    let device_a = Device {
        id: device_a_id,
        organization_id: org_a,
        registered_by_user_id: Some("user_a".into()),
        name: "Device Org A".into(),
        hostname: "box-a".into(),
        platform: "linux".into(),
        architecture: "x86_64".into(),
        created_at: OffsetDateTime::now_utc(),
        last_seen_at: OffsetDateTime::now_utc(),
        revoked_at: None,
        capabilities: vec!["scan".into()],
        version: Some("0.1.0".into()),
        agent_enabled: false,
        agent_status: None,
        current_job_id: None,
        completed_jobs_count: 0,
    };
    state.devices.save_device(&device_a).await.unwrap();
    state
        .devices
        .save_device_token(&token_a_hash, device_a_id, org_a)
        .await
        .unwrap();

    // Create Device B for Org B
    let device_b_id = Uuid::new_v4();
    let token_b = "mlt_token_for_org_b_device_789012";
    let token_b_hash = format!("{:x}", Sha256::digest(token_b.as_bytes()));
    let device_b = Device {
        id: device_b_id,
        organization_id: org_b,
        registered_by_user_id: Some("user_b".into()),
        name: "Device Org B".into(),
        hostname: "box-b".into(),
        platform: "linux".into(),
        architecture: "x86_64".into(),
        created_at: OffsetDateTime::now_utc(),
        last_seen_at: OffsetDateTime::now_utc(),
        revoked_at: None,
        capabilities: vec!["scan".into()],
        version: Some("0.1.0".into()),
        agent_enabled: false,
        agent_status: None,
        current_job_id: None,
        completed_jobs_count: 0,
    };
    state.devices.save_device(&device_b).await.unwrap();
    state
        .devices
        .save_device_token(&token_b_hash, device_b_id, org_b)
        .await
        .unwrap();

    // Sync assessment from Device A
    let assessment_a_id = Uuid::new_v4();
    let assessment_a = AssessmentRecord::new_capture(
        assessment_a_id,
        "Org A Capture Assessment".into(),
        CaptureMetadata {
            capture_name: "orga.pcap".into(),
            capture_hash: "hasha".into(),
            capture_size_bytes: 1000,
            time_range_start: None,
            time_range_end: None,
        },
        OffsetDateTime::now_utc(),
        vec!["SMTP".into()],
        vec![],
        vec![],
        vec![],
        vec![],
        90.0,
        "A".into(),
        vec![],
        "LOW".into(),
        "Rationale".into(),
        0.0,
        serde_json::json!({}),
    );

    let sync_a_body = serde_json::json!({
        "client_sync_id": assessment_a_id.to_string(),
        "assessment": assessment_a,
    });

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/assessments/sync")
                .header("Authorization", format!("Bearer {token_a}"))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&sync_a_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    // Sync assessment from Device B
    let assessment_b_id = Uuid::new_v4();
    let assessment_b = AssessmentRecord::new_capture(
        assessment_b_id,
        "Org B Capture Assessment".into(),
        CaptureMetadata {
            capture_name: "orgb.pcap".into(),
            capture_hash: "hashb".into(),
            capture_size_bytes: 2000,
            time_range_start: None,
            time_range_end: None,
        },
        OffsetDateTime::now_utc(),
        vec!["IMAP".into()],
        vec![],
        vec![],
        vec![],
        vec![],
        80.0,
        "B".into(),
        vec![],
        "MEDIUM".into(),
        "Rationale".into(),
        0.0,
        serde_json::json!({}),
    );

    let sync_b_body = serde_json::json!({
        "client_sync_id": assessment_b_id.to_string(),
        "assessment": assessment_b,
    });

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/assessments/sync")
                .header("Authorization", format!("Bearer {token_b}"))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&sync_b_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    // Device A lists assessments -> MUST ONLY see assessment A
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/assessments")
                .header("Authorization", format!("Bearer {token_a}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let list_a: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(list_a.len(), 1);
    assert_eq!(list_a[0]["id"], assessment_a_id.to_string());

    // Device B lists assessments -> MUST ONLY see assessment B
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/assessments")
                .header("Authorization", format!("Bearer {token_b}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let list_b: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(list_b.len(), 1);
    assert_eq!(list_b[0]["id"], assessment_b_id.to_string());

    // Cross-tenant access: Device B attempts to read assessment A directly -> MUST return 404
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/assessments/{assessment_a_id}"))
                .header("Authorization", format!("Bearer {token_b}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // Cross-tenant device revocation: Device A attempts to revoke Device B -> MUST return 403 Forbidden
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/devices/{device_b_id}"))
                .header("Authorization", format!("Bearer {token_a}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // Device B revokes Device B -> MUST return 200 OK
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/devices/{device_b_id}"))
                .header("Authorization", format!("Bearer {token_b}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
}
