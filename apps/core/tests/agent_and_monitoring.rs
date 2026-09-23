use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use mailent_core::{AppState, api::create_router, auth::protect};
use mailent_domain::{
    AgentJob, AssessmentRecord, DEFAULT_ORG_ID, DiscoveredEndpoint, Finding, FindingCategory,
    FindingSeverity, InfrastructureMetadata, InvestigationStatus, JobState, Organization,
    PriorityLevel, RiskLevel,
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
async fn test_agent_heartbeat_and_status() {
    let (state, app) = setup_test_app().await;
    let (token, device_id) =
        create_and_approve_device(&app, "ThinkPad-Agent", DEFAULT_ORG_ID).await;

    // Send heartbeat
    let heartbeat_req = serde_json::json!({
        "version": "0.1.0",
        "capabilities": ["infrastructure_scan", "active_verification"],
        "status": "idle"
    });

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/heartbeat")
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&heartbeat_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    // Verify device record has updated agent status
    let dev = state
        .devices
        .find_device_by_id(device_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(dev.agent_status.as_deref(), Some("idle"));
    assert_eq!(dev.version.as_deref(), Some("0.1.0"));
    assert!(dev.agent_enabled);
}

#[tokio::test]
async fn test_monitor_creation_and_run_now() {
    let (_state, app) = setup_test_app().await;
    let (token, device_id) = create_and_approve_device(&app, "Lab-Scanner", DEFAULT_ORG_ID).await;

    // 1. Create a monitor for example.com
    let create_req = serde_json::json!({
        "domain": "example.com",
        "cadence": "daily",
        "target": {
            "type": "agent",
            "agent_id": device_id
        }
    });

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/monitors")
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&create_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::CREATED);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let monitor_res: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let monitor_id = monitor_res["id"].as_str().unwrap();

    // 2. Trigger run now
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/monitors/{monitor_id}/run_now"))
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let run_res: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let job_id = run_res["job_id"].as_str().unwrap();

    // 3. Agent polls for jobs
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/jobs/poll")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let poll_res: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(!poll_res["job"].is_null());
    assert_eq!(poll_res["job"]["id"].as_str().unwrap(), job_id);

    // 4. Agent completes job with assessment
    let assessment = create_sample_infra_assessment(
        "example.com",
        95.0,
        "A",
        vec![DiscoveredEndpoint {
            service: "smtp".into(),
            host: "mail.example.com".into(),
            port: 25,
            priority: Some(10),
            resolved_ips: vec!["198.51.100.1".into()],
        }],
        OffsetDateTime::now_utc(),
    );

    let complete_req = serde_json::json!({
        "assessment": assessment,
        "output_summary": { "status": "ok" }
    });

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/agent/jobs/{job_id}/complete"))
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&complete_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    // 5. Verify history shows the completed assessment
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/monitors/domain/example.com/history")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let hist_res: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(hist_res["domain"], "example.com");
    let history_items = hist_res["history"].as_array().unwrap();
    assert_eq!(history_items.len(), 1);
    assert_eq!(history_items[0]["posture_score"], 95.0);
}

#[tokio::test]
async fn test_historical_drift_and_security_regression_detection() {
    let (_state, app) = setup_test_app().await;
    let (token, _device_id) =
        create_and_approve_device(&app, "ThinkPad-Agent", DEFAULT_ORG_ID).await;
    let now = OffsetDateTime::now_utc();

    // Run 1: High posture (baseline) 5 minutes ago
    let assess1 = create_sample_infra_assessment(
        "drift-target.example",
        95.0,
        "A",
        vec![DiscoveredEndpoint {
            service: "smtp".into(),
            host: "mx1.drift-target.example".into(),
            port: 25,
            priority: Some(10),
            resolved_ips: vec!["198.51.100.1".into()],
        }],
        now - time::Duration::minutes(5),
    );

    // Sync Run 1 assessment
    let sync1_req = serde_json::json!({
        "assessment": assess1,
    });
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/assessments/sync")
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&sync1_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Run 2: Endpoint removed + Posture dropped (security degradation) now
    let assess2 = create_sample_infra_assessment(
        "drift-target.example",
        65.0,
        "D",
        vec![DiscoveredEndpoint {
            service: "smtp".into(),
            host: "mx-new.drift-target.example".into(),
            port: 25,
            priority: Some(20),
            resolved_ips: vec!["198.51.100.2".into()],
        }],
        now,
    );

    let sync2_req = serde_json::json!({
        "assessment": assess2,
    });
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/assessments/sync")
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&sync2_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Query domain history to inspect "What changed?"
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/monitors/domain/drift-target.example/history")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let hist_res: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let history_items = hist_res["history"].as_array().unwrap();
    assert_eq!(history_items.len(), 2);

    // Most recent scan (assess2) should have drift events
    let recent = &history_items[0];
    let drift_events = recent["drift_events"].as_array().unwrap();
    assert!(
        !drift_events.is_empty(),
        "Expected drift events between consecutive scans"
    );

    // Posture changed and endpoint added/removed should be detected
    let kinds: Vec<&str> = drift_events
        .iter()
        .filter_map(|d| d["kind"].as_str())
        .collect();
    assert!(
        kinds.contains(&"endpoint_added")
            || kinds.contains(&"posture_changed")
            || kinds.contains(&"EndpointAdded")
            || kinds.contains(&"PostureChanged")
    );
}

#[tokio::test]
async fn test_lease_expiration_and_recovery() {
    let (state, _app) = setup_test_app().await;
    let now = OffsetDateTime::now_utc();

    let dev_id_1 = Uuid::new_v4();
    let dev_id_2 = Uuid::new_v4();
    let org_id = DEFAULT_ORG_ID;

    // Create a pending job targeting any agent in org
    let mut job = AgentJob::new_infrastructure_assessment(
        org_id,
        "expire-test.com".into(),
        120,
        None,
        Some("expire-key-1".into()),
        None,
    );
    job.execution_target = mailent_domain::JobExecutionTarget::Agent(Uuid::nil());
    state.jobs.create_job(&job).await.unwrap();

    // Device 1 leases job for 10 seconds
    let leased_job = state
        .jobs
        .lease_next_job(dev_id_1, org_id, now, 10)
        .await
        .unwrap();
    assert!(leased_job.is_some());
    let j = leased_job.unwrap();
    assert_eq!(j.state, JobState::Leased);

    // Device 2 attempts to lease -> none available
    let second_lease = state
        .jobs
        .lease_next_job(dev_id_2, org_id, now, 10)
        .await
        .unwrap();
    assert!(second_lease.is_none());

    // Fast-forward time past 10 seconds (now + 15s) and trigger lease recovery
    let future = now + time::Duration::seconds(15);
    let recovered_count = state.jobs.recover_expired_leases(future).await.unwrap();
    assert_eq!(recovered_count, 1);

    // Device 2 can now lease the recovered job!
    let second_lease = state
        .jobs
        .lease_next_job(dev_id_2, org_id, future, 10)
        .await
        .unwrap();
    assert!(second_lease.is_some());
    assert_eq!(second_lease.unwrap().id, j.id);
}

#[tokio::test]
async fn test_multi_tenant_agent_and_monitor_isolation() {
    let (state, app) = setup_test_app().await;

    // Org A and Org B
    let org_a = DEFAULT_ORG_ID;
    let org_b = Uuid::new_v4();
    state
        .organizations
        .save(&Organization {
            id: org_b,
            name: "Tenant B".into(),
            slug: "tenant-b".into(),
            created_at: OffsetDateTime::now_utc(),
        })
        .await
        .unwrap();

    let (token_a, device_a) = create_and_approve_device(&app, "Agent-Org-A", org_a).await;

    // Register Device B directly for Org B
    let device_b_id = Uuid::new_v4();
    let token_b = "mlt_token_for_org_b_device_789012";
    use sha2::{Digest, Sha256};
    let token_b_hash = format!("{:x}", Sha256::digest(token_b.as_bytes()));
    let device_b = mailent_domain::Device {
        id: device_b_id,
        organization_id: org_b,
        registered_by_user_id: Some("user_b".into()),
        name: "Agent-Org-B".into(),
        hostname: "box-b".into(),
        platform: "linux".into(),
        architecture: "x86_64".into(),
        created_at: OffsetDateTime::now_utc(),
        last_seen_at: OffsetDateTime::now_utc(),
        revoked_at: None,
        capabilities: vec!["scan".into()],
        version: Some("0.1.0".into()),
        agent_enabled: true,
        agent_status: Some("idle".into()),
        current_job_id: None,
        completed_jobs_count: 0,
    };
    state.devices.save_device(&device_b).await.unwrap();
    state
        .devices
        .save_device_token(&token_b_hash, device_b_id, org_b)
        .await
        .unwrap();

    // Create monitor in Org A
    let create_req = serde_json::json!({
        "domain": "tenant-a.corp",
        "cadence": "hourly",
        "target": {
            "type": "agent",
            "agent_id": device_a
        }
    });

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/monitors")
                .header("Authorization", format!("Bearer {token_a}"))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&create_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::CREATED);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let mon_a: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let mon_id_a = mon_a["id"].as_str().unwrap();

    // Agent B tries to access Monitor A -> 403 Forbidden
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/monitors/{mon_id_a}"))
                .header("Authorization", format!("Bearer {token_b}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // Agent B lists monitors -> should NOT see Monitor A
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/monitors")
                .header("Authorization", format!("Bearer {token_b}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let mon_list_b: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(mon_list_b.as_array().unwrap().len(), 0);

    // Agent B polls for jobs -> does NOT receive Org A's jobs
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/jobs/poll")
                .header("Authorization", format!("Bearer {token_b}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let poll_b: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(poll_b["job"].is_null());
}

#[tokio::test]
async fn test_investigation_creation_enrichment_and_deduplication_via_agent_job() {
    let (state, app) = setup_test_app().await;
    let org_id = DEFAULT_ORG_ID;
    let (token, device_id) = create_and_approve_device(&app, "investigation-agent", org_id).await;

    // Enable agent
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/enroll")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let domain = "target-corp.com";
    let asset_id = Uuid::new_v5(&Uuid::NAMESPACE_OID, domain.as_bytes());
    let now = OffsetDateTime::now_utc();

    // 1. Establish baseline assessment (good state, score 95.0, grade "A")
    let baseline = create_sample_infra_assessment(
        domain,
        95.0,
        "A",
        vec![DiscoveredEndpoint {
            service: "smtp".into(),
            host: "mail.target-corp.com".into(),
            port: 25,
            priority: Some(10),
            resolved_ips: vec!["192.0.2.1".into()],
        }],
        now - time::Duration::hours(2),
    )
    .with_organization(org_id);
    state.assessments.save(&baseline).await.unwrap();

    // 2. First Job: Security Regression (STARTTLS Lost + Score drops to 30.0 + High finding introduced)
    let job1 = AgentJob::new_infrastructure_assessment(
        org_id,
        domain.into(),
        60,
        Some(device_id),
        None,
        None,
    );
    state.jobs.create_job(&job1).await.unwrap();
    let leased_job1 = state
        .jobs
        .lease_next_job(device_id, org_id, now, 600)
        .await
        .unwrap()
        .expect("job1 should be leased");

    let finding_starttls = Finding {
        id: Uuid::new_v4(),
        rule_id: "STARTTLS_MISSING".to_string(),
        policy_name: "mailent-infra-v1".to_string(),
        policy_version: "1.0.0".to_string(),
        reference: "RFC-3207".to_string(),
        severity: FindingSeverity::High,
        category: FindingCategory::TlsConfiguration,
        title: "STARTTLS Missing".to_string(),
        description: "STARTTLS is not advertised on port 25".to_string(),
        remediation: "Enable STARTTLS on the SMTP server".to_string(),
        affected_count: 1,
        first_seen: now,
        last_seen: now,
        evidence: Vec::new(),
        organization_id: Some(org_id),
    };

    let degraded_assessment1 = create_sample_infra_assessment(
        domain,
        30.0,
        "F",
        vec![DiscoveredEndpoint {
            service: "smtp".into(),
            host: "mail.target-corp.com".into(),
            port: 25,
            priority: Some(10),
            resolved_ips: vec!["192.0.2.1".into()],
        }],
        now,
    );

    let complete_payload1 = serde_json::json!({
        "assessment": degraded_assessment1,
        "findings": [finding_starttls],
        "assets": [],
        "sessions": []
    });

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/agent/jobs/{}/complete", leased_job1.id))
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&complete_payload1).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    // Verify investigation was CREATED
    let invs = state.investigations.list_for_asset(asset_id).await.unwrap();
    assert_eq!(invs.len(), 1, "Exactly one investigation should be opened");
    let initial_inv = &invs[0];
    let inv_id = initial_inv.id;
    assert_eq!(initial_inv.status, InvestigationStatus::Open);
    assert!(
        initial_inv
            .finding_ids
            .contains(&"STARTTLS_MISSING".to_string())
    );
    assert!(!initial_inv.drift_event_ids.is_empty());

    // 3. Second Job: Additional Critical regression (Certificate expired) -> ENRICHMENT
    let job2 = AgentJob::new_infrastructure_assessment(
        org_id,
        domain.into(),
        60,
        Some(device_id),
        None,
        None,
    );
    state.jobs.create_job(&job2).await.unwrap();
    let leased_job2 = state
        .jobs
        .lease_next_job(device_id, org_id, now + time::Duration::minutes(5), 600)
        .await
        .unwrap()
        .expect("job2 should be leased");

    let finding_cert = Finding {
        id: Uuid::new_v4(),
        rule_id: "CERTIFICATE_EXPIRED".to_string(),
        policy_name: "mailent-infra-v1".to_string(),
        policy_version: "1.0.0".to_string(),
        reference: "RFC-5280".to_string(),
        severity: FindingSeverity::Critical,
        category: FindingCategory::Certificate,
        title: "Certificate Expired".to_string(),
        description: "TLS certificate expired 3 days ago".to_string(),
        remediation: "Renew TLS certificate".to_string(),
        affected_count: 1,
        first_seen: now + time::Duration::minutes(5),
        last_seen: now + time::Duration::minutes(5),
        evidence: Vec::new(),
        organization_id: Some(org_id),
    };

    let degraded_assessment2 = create_sample_infra_assessment(
        domain,
        20.0,
        "F",
        vec![DiscoveredEndpoint {
            service: "smtp".into(),
            host: "mail.target-corp.com".into(),
            port: 25,
            priority: Some(10),
            resolved_ips: vec!["192.0.2.1".into()],
        }],
        now + time::Duration::minutes(5),
    );

    let complete_payload2 = serde_json::json!({
        "assessment": degraded_assessment2,
        "findings": [finding_cert],
        "assets": [],
        "sessions": []
    });

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/agent/jobs/{}/complete", leased_job2.id))
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&complete_payload2).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    // Verify investigation was ENRICHED, NOT duplicated
    let invs2 = state.investigations.list_for_asset(asset_id).await.unwrap();
    assert_eq!(
        invs2.len(),
        1,
        "Should still be exactly one investigation (enriched, not duplicated)"
    );
    let enriched_inv = &invs2[0];
    assert_eq!(
        enriched_inv.id, inv_id,
        "Investigation ID must be preserved"
    );
    assert_eq!(
        enriched_inv.risk,
        RiskLevel::Critical,
        "Risk level elevated to Critical"
    );
    assert_eq!(
        enriched_inv.priority,
        PriorityLevel::Immediate,
        "Priority elevated to Immediate"
    );
    assert!(
        enriched_inv
            .finding_ids
            .contains(&"CERTIFICATE_EXPIRED".to_string())
    );

    // 4. Third Job: Repeated scan with identical unresolved issues -> DEDUPLICATION
    let job3 = AgentJob::new_infrastructure_assessment(
        org_id,
        domain.into(),
        60,
        Some(device_id),
        None,
        None,
    );
    state.jobs.create_job(&job3).await.unwrap();
    let leased_job3 = state
        .jobs
        .lease_next_job(device_id, org_id, now + time::Duration::minutes(10), 600)
        .await
        .unwrap()
        .expect("job3 should be leased");

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/agent/jobs/{}/complete", leased_job3.id))
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&complete_payload2).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    let invs3 = state.investigations.list_for_asset(asset_id).await.unwrap();
    assert_eq!(
        invs3.len(),
        1,
        "Repeated scans must not create duplicate cases"
    );
    assert_eq!(invs3[0].id, inv_id);
}

#[tokio::test]
async fn test_benign_drift_creates_no_investigation_via_agent_job() {
    let (state, app) = setup_test_app().await;
    let org_id = DEFAULT_ORG_ID;
    let (token, device_id) = create_and_approve_device(&app, "benign-agent", org_id).await;

    // Enable agent
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/enroll")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let domain = "benign-corp.com";
    let asset_id = Uuid::new_v5(&Uuid::NAMESPACE_OID, domain.as_bytes());
    let now = OffsetDateTime::now_utc();

    // 1. Establish baseline (1 endpoint, score 90.0)
    let baseline = create_sample_infra_assessment(
        domain,
        90.0,
        "A",
        vec![DiscoveredEndpoint {
            service: "smtp".into(),
            host: "mail1.benign-corp.com".into(),
            port: 25,
            priority: Some(10),
            resolved_ips: vec!["192.0.2.1".into()],
        }],
        now - time::Duration::hours(2),
    )
    .with_organization(org_id);
    state.assessments.save(&baseline).await.unwrap();

    // 2. Complete job with benign change: MX / Endpoint added, score unchanged, 0 findings
    let job = AgentJob::new_infrastructure_assessment(
        org_id,
        domain.into(),
        60,
        Some(device_id),
        None,
        None,
    );
    state.jobs.create_job(&job).await.unwrap();
    let leased_job = state
        .jobs
        .lease_next_job(device_id, org_id, now, 600)
        .await
        .unwrap()
        .expect("job should be leased");

    let updated_assessment = create_sample_infra_assessment(
        domain,
        90.0,
        "A",
        vec![
            DiscoveredEndpoint {
                service: "smtp".into(),
                host: "mail1.benign-corp.com".into(),
                port: 25,
                priority: Some(10),
                resolved_ips: vec!["192.0.2.1".into()],
            },
            DiscoveredEndpoint {
                service: "smtp".into(),
                host: "mail2.benign-corp.com".into(),
                port: 25,
                priority: Some(20),
                resolved_ips: vec!["192.0.2.2".into()],
            },
        ],
        now,
    );

    let complete_payload = serde_json::json!({
        "assessment": updated_assessment,
        "findings": [],
        "assets": [],
        "sessions": []
    });

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/agent/jobs/{}/complete", leased_job.id))
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&complete_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    // Verify drift event was recorded in history
    let drifts = state
        .assets
        .list_drift_events(Some(asset_id), 10)
        .await
        .unwrap();
    assert!(
        !drifts.is_empty(),
        "Benign drift should be captured in asset history"
    );

    // Verify NO investigation was opened for benign drift
    let invs = state.investigations.list_for_asset(asset_id).await.unwrap();
    assert_eq!(invs.len(), 0, "Benign drift must NOT open an investigation");
}

#[tokio::test]
async fn test_concurrent_job_leasing_race_condition() {
    let (state, app) = setup_test_app().await;
    let org_id = Uuid::new_v4();
    state
        .organizations
        .save(&Organization {
            id: org_id,
            name: "Race Condition Test Org".to_string(),
            slug: "race-org".to_string(),
            created_at: OffsetDateTime::now_utc(),
        })
        .await
        .unwrap();

    // Register 5 distinct agent devices
    let mut tokens = Vec::new();
    let mut device_ids = Vec::new();
    for i in 1..=5 {
        let (token, dev_id) = create_and_approve_device(&app, &format!("Agent-{i}"), org_id).await;
        tokens.push(token);
        device_ids.push(dev_id);
    }

    // Create exactly ONE pending job targetable by any agent in the org
    let job_id = Uuid::new_v4();
    let job = AgentJob {
        id: job_id,
        organization_id: org_id,
        target_agent_id: None, // Any agent in org can take it
        execution_target: mailent_domain::JobExecutionTarget::Agent(device_ids[0]),
        job_type: mailent_domain::AgentJobType::InfrastructureAssessment {
            domain: "concurrency.test".to_string(),
            timeout_seconds: 30,
        },
        state: JobState::Pending,
        created_at: OffsetDateTime::now_utc(),
        available_at: OffsetDateTime::now_utc(),
        leased_at: None,
        lease_expires_at: None,
        started_at: None,
        completed_at: None,
        attempt: 0,
        max_attempts: 3,
        result_assessment_id: None,
        last_error: None,
        idempotency_key: Some(format!("race-test-{}", job_id)),
        monitor_id: None,
    };
    state.jobs.create_job(&job).await.unwrap();

    // Concurrently poll from all 5 agents
    let mut handles = Vec::new();
    for token in &tokens {
        let app_clone = app.clone();
        let tok = token.clone();
        handles.push(tokio::spawn(async move {
            let res = app_clone
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/agent/jobs/poll")
                        .header("Authorization", format!("Bearer {tok}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let bytes = res.into_body().collect().await.unwrap().to_bytes();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            !body["job"].is_null()
        }));
    }

    let mut leased_count = 0;
    for handle in handles {
        let got_job = handle.await.unwrap();
        if got_job {
            leased_count += 1;
        }
    }

    // Exactly 1 agent must have won the lease; 4 must have received null
    assert_eq!(
        leased_count, 1,
        "Exactly ONE agent must lease the job under concurrent polling"
    );

    // Verify stored job state is Leased with attempt = 1
    let stored = state.jobs.find_by_id(job_id).await.unwrap().unwrap();
    assert_eq!(stored.state, JobState::Leased);
    assert_eq!(stored.attempt, 1);
    assert!(stored.leased_at.is_some());
}
