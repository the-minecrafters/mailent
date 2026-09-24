use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use mailent_core::{AppState, api::create_router, auth::protect};
use mailent_domain::{
    AgentJob, AssessmentRecord, DEFAULT_ORG_ID, DiscoveredEndpoint, InfrastructureMetadata,
    JobState,
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

#[tokio::test]
async fn review_report_export_rejects_another_workspace() {
    let (state, app) = setup_test_app().await;
    let (token, _) = create_and_approve_device(&app, "review-device", DEFAULT_ORG_ID).await;
    let other_org = Uuid::new_v4();
    let assessment = create_sample_infra_assessment(
        "private-other-workspace.test",
        90.0,
        "A",
        vec![],
        OffsetDateTime::now_utc(),
    )
    .with_organization(other_org);
    state.assessments.save(&assessment).await.unwrap();
    for suffix in [
        "",
        "/report?format=json",
        "/report?format=html",
        "/report?format=pdf",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/assessments/{}{suffix}", assessment.id))
                    .header("Authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "Cross-workspace endpoint {suffix} must not return private data"
        );
    }
}

#[tokio::test]
async fn review_revoke_cancels_jobs_beyond_first_200_records() {
    let (state, app) = setup_test_app().await;
    let (_, device_id) = create_and_approve_device(&app, "review-device", DEFAULT_ORG_ID).await;
    let mut ids = Vec::new();
    for _ in 0..201 {
        let job = AgentJob::new_infrastructure_assessment(
            DEFAULT_ORG_ID,
            "review.test".into(),
            120,
            Some(device_id),
            None,
            None,
        );
        ids.push(job.id);
        state.jobs.create_job(&job).await.unwrap();
    }
    let mut untouched = Vec::new();
    for (org, device, status) in [
        (Uuid::new_v4(), device_id, JobState::Pending),
        (DEFAULT_ORG_ID, Uuid::new_v4(), JobState::Pending),
        (DEFAULT_ORG_ID, device_id, JobState::Completed),
        (DEFAULT_ORG_ID, device_id, JobState::Failed),
    ] {
        let mut job = AgentJob::new_infrastructure_assessment(
            org,
            "other.test".into(),
            120,
            Some(device),
            None,
            None,
        );
        job.state = status;
        state.jobs.create_job(&job).await.unwrap();
        untouched.push(job);
    }
    for status in [JobState::Leased, JobState::Running] {
        let mut job = AgentJob::new_infrastructure_assessment(
            DEFAULT_ORG_ID,
            "active.test".into(),
            120,
            Some(device_id),
            None,
            None,
        );
        job.state = status;
        job.lease_expires_at = Some(OffsetDateTime::now_utc() + time::Duration::minutes(5));
        ids.push(job.id);
        state.jobs.create_job(&job).await.unwrap();
    }
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/devices/{device_id}"))
                .header("x-mailent-org", DEFAULT_ORG_ID.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    for id in ids {
        let job = state.jobs.find_by_id(id).await.unwrap().unwrap();
        assert_eq!(
            job.state,
            JobState::Canceled,
            "Revocation left job {id} active"
        );
        assert!(job.completed_at.is_some());
        assert!(job.lease_expires_at.is_none());
    }
    for expected in untouched {
        let actual = state.jobs.find_by_id(expected.id).await.unwrap().unwrap();
        assert_eq!(
            actual.state, expected.state,
            "Unrelated or terminal jobs must remain unchanged"
        );
    }
}

#[tokio::test]
async fn review_device_revocation_rejects_subsequent_token_requests() {
    let (_state, app) = setup_test_app().await;
    let (token, device_id) = create_and_approve_device(&app, "revokable-device", DEFAULT_ORG_ID).await;

    // Verify token works before revocation
    let pre_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/devices/status")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pre_res.status(), StatusCode::OK);

    // Revoke device
    let revoke_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/devices/{device_id}"))
                .header("x-mailent-org", DEFAULT_ORG_ID.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoke_res.status(), StatusCode::OK);

    // Verify token is rejected immediately after revocation
    let post_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/devices/status")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(post_res.status(), StatusCode::UNAUTHORIZED);
}
