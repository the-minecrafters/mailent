use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use mailent_core::{api::create_router, state::AppState};
use mailent_domain::{
    CertificateObservation, CertificateReference, CipherSuite, DnssecState, EmailProtocol,
    KeyExchange, MtaStsMode, MtaStsPolicy, NetworkFlow, NormalizedObservation,
    ObservationProvenance, StartTlsState, TlsRptPolicy, TlsVersion, TlsaRecord, ValidityPeriod,
};
use serde_json::Value;
use time::{Duration, OffsetDateTime};
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
async fn test_end_to_end_intelligence_baseline_investigation_slice() {
    let state = AppState::new();
    let now = OffsetDateTime::now_utc();

    // 1. Seed External Intelligence for "example.com"
    let mta_sts = MtaStsPolicy {
        domain: "example.com".to_string(),
        version: "STSv1".to_string(),
        mode: MtaStsMode::Enforce,
        mx_patterns: vec!["mail.example.com".to_string()],
        max_age_seconds: 86400,
        dnssec: DnssecState::Secure,
        checked_at: now,
    };
    state
        .intelligence
        .save_mta_sts_policy(&mta_sts)
        .await
        .unwrap();

    let tlsa = TlsaRecord {
        domain: "example.com".to_string(),
        mx_host: "mail.example.com".to_string(),
        port: 25,
        usage: 3,
        selector: 1,
        matching_type: 1,
        cert_association_data: "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
            .to_string(),
        dnssec: DnssecState::Secure,
        checked_at: now,
    };
    state
        .intelligence
        .save_tlsa_records("example.com", std::slice::from_ref(&tlsa))
        .await
        .unwrap();
    state
        .intelligence
        .save_tlsa_records("mail.example.com", std::slice::from_ref(&tlsa))
        .await
        .unwrap();

    let tls_rpt = TlsRptPolicy {
        domain: "example.com".to_string(),
        rua: vec!["mailto:tls-reports@example.com".to_string()],
        checked_at: now,
    };
    state
        .intelligence
        .save_tls_rpt_policy(&tls_rpt)
        .await
        .unwrap();

    let app = create_router(state.clone());

    // 2. Submit initial healthy modern session to build historical baseline
    let good_obs = NormalizedObservation {
        observation_id: Uuid::new_v4(),
        timestamp: now - Duration::minutes(10),
        sensor_id: "sensor-prod-01".to_string(),
        provenance: ObservationProvenance {
            source: "pcap".to_string(),
            parser: "zeek".to_string(),
            parser_version: "6.0".to_string(),
        },
        flow: NetworkFlow {
            src_ip: "192.168.1.50".to_string(),
            src_port: 45000,
            dst_ip: "10.0.0.25".to_string(),
            dst_port: 25,
        },
        protocol: EmailProtocol::Smtp,
        starttls_state: Some(StartTlsState::TlsEstablished),
        tls_version: Some(TlsVersion::Tls13),
        cipher_suite: Some(CipherSuite {
            id: Some(0x1301),
            name: "TLS_AES_128_GCM_SHA256".to_string(),
        }),
        key_exchange: Some(KeyExchange::Ecdhe),
        certificate: Some(CertificateObservation {
            reference: CertificateReference {
                sha256_fingerprint:
                    "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff".to_string(),
                subject: "CN=mail.example.com".to_string(),
                issuer: "CN=Let's Encrypt Authority".to_string(),
            },
            validity: ValidityPeriod {
                not_before: now - Duration::days(30),
                not_after: now + Duration::days(60),
            },
            is_self_signed: Some(false),
            san: vec!["mail.example.com".to_string()],
        }),
        capture: None,
        raw_metadata: None,
    };

    // 2. Submit initial healthy modern sessions to build historical baseline (5 samples)
    let mut asset_id_str = String::new();
    let mut asset_id = Uuid::nil();

    for i in 0..5 {
        let mut obs = good_obs.clone();
        obs.observation_id = Uuid::new_v4();
        obs.timestamp = now - Duration::minutes(15 - i);

        let req = Request::builder()
            .uri("/api/v1/observations")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&obs).unwrap()))
            .unwrap();

        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let res_json: Value = serde_json::from_slice(&body).unwrap();
        asset_id_str = res_json["asset_id"].as_str().unwrap().to_string();
        asset_id = Uuid::parse_str(&asset_id_str).unwrap();
    }

    // 3. Verify Baseline API for asset
    let req = Request::builder()
        .uri(format!("/api/v1/assets/{asset_id}/baseline"))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let baseline_json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(baseline_json["sample_count"], 5);
    assert_eq!(baseline_json["starttls_success_rate"], 1.0);

    // 4. Submit Degraded & Rogue session:
    // - Protocol downgrade to TLS 1.0
    // - Static RSA cipher without PFS
    // - Rogue Certificate with mismatched fingerprint (triggers DANE mismatch & CT anomaly)
    let bad_obs = NormalizedObservation {
        observation_id: Uuid::new_v4(),
        timestamp: now,
        sensor_id: "sensor-prod-01".to_string(),
        provenance: ObservationProvenance {
            source: "pcap".to_string(),
            parser: "zeek".to_string(),
            parser_version: "6.0".to_string(),
        },
        flow: NetworkFlow {
            src_ip: "192.168.1.51".to_string(),
            src_port: 45001,
            dst_ip: "10.0.0.25".to_string(),
            dst_port: 25,
        },
        protocol: EmailProtocol::Smtp,
        starttls_state: Some(StartTlsState::TlsEstablished),
        tls_version: Some(TlsVersion::Tls10),
        cipher_suite: Some(CipherSuite {
            id: Some(0x000A),
            name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA".to_string(),
        }),
        key_exchange: Some(KeyExchange::RsaStatic),
        certificate: Some(CertificateObservation {
            reference: CertificateReference {
                sha256_fingerprint:
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
                subject: "CN=mail.example.com".to_string(),
                issuer: "CN=Rogue Untrusted CA".to_string(),
            },
            validity: ValidityPeriod {
                not_before: now - Duration::days(5),
                not_after: now + Duration::days(20),
            },
            is_self_signed: Some(true),
            san: vec!["mail.example.com".to_string()],
        }),
        capture: None,
        raw_metadata: None,
    };

    let req = Request::builder()
        .uri("/api/v1/observations")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&bad_obs).unwrap()))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // 5. Verify Anomalies API
    let req = Request::builder()
        .uri(format!("/api/v1/assets/{asset_id}/anomalies"))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let anomalies_json: Value = serde_json::from_slice(&body).unwrap();
    let anomalies = anomalies_json.as_array().expect("array of anomalies");
    assert!(
        !anomalies.is_empty(),
        "Should generate baseline & intelligence anomalies"
    );

    let signal_types: Vec<&str> = anomalies
        .iter()
        .map(|a| a["signal"].as_str().unwrap())
        .collect();
    // Verify DANE mismatch and baseline deviation signals
    assert!(signal_types.contains(&"NewDaneMismatch"));
    assert!(signal_types.contains(&"UnseenTlsVersion") || signal_types.contains(&"RareCipher"));

    // 6. Verify Investigation API
    let req = Request::builder()
        .uri("/api/v1/investigations")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let investigations_json: Value = serde_json::from_slice(&body).unwrap();
    let investigations = investigations_json.as_array().unwrap();
    assert_eq!(
        investigations.len(),
        1,
        "Should have 1 consolidated investigation for the asset"
    );

    let inv = &investigations[0];
    assert_eq!(inv["asset_id"], asset_id_str);
    assert_eq!(inv["status"], "open");
    assert!(inv["risk"] == "critical" || inv["risk"] == "high");
    assert!(inv["priority"] == "immediate" || inv["priority"] == "high");

    let inv_id = inv["id"].as_str().unwrap();

    // 7. Verify Investigation status update
    let req = Request::builder()
        .uri(format!("/api/v1/investigations/{inv_id}/status"))
        .method("PATCH")
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"status": "under_review"}"#))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Verify updated status
    let req = Request::builder()
        .uri(format!("/api/v1/investigations/{inv_id}"))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let single_inv: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(single_inv["status"], "under_review");

    // 8. Ingest TLS-RPT Report
    let tls_rpt_json = r#"{
        "organization-name": "Test Reports Inc",
        "date-range": {
            "start-datetime": "2026-09-22T00:00:00Z",
            "end-datetime": "2026-09-22T23:59:59Z"
        },
        "contact-info": "admin@example.com",
        "report-id": "rpt-20260922-001",
        "policies": [
            {
                "policy": {
                    "policy-type": "sts",
                    "policy-string": ["version: STSv1", "mode: enforce", "mx: mail.example.com"],
                    "policy-domain": "example.com"
                },
                "summary": {
                    "total-successful-session-count": 1000,
                    "total-failure-session-count": 12
                },
                "failure-details": [
                    {
                        "result-type": "certificate-host-mismatch",
                        "receiving-mx-hostname": "mail.example.com",
                        "failed-session-count": 12
                    }
                ]
            }
        ]
    }"#;

    let req = Request::builder()
        .uri("/api/v1/tls-rpt/reports")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(tls_rpt_json))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    // 9. Verify Intelligence query endpoint
    let req = Request::builder()
        .uri("/api/v1/intelligence/example.com")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let intel_res: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(intel_res["mta_sts_policy"]["mode"], "enforce");
    assert_eq!(intel_res["tlsa_records"].as_array().unwrap().len(), 1);
    assert_eq!(
        intel_res["recent_tls_rpt_reports"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // 10. Verify Decisions API
    let req = Request::builder()
        .uri("/api/v1/decisions")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let decisions_res: Value = serde_json::from_slice(&body).unwrap();
    assert!(!decisions_res.as_array().unwrap().is_empty());

    // 11. Verify Coverage Metrics API
    let req = Request::builder()
        .uri("/api/v1/metrics/coverage")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let metrics_res: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(metrics_res["total_assets"], 1);
    assert_eq!(metrics_res["assets_with_baseline"], 1);
    assert_eq!(metrics_res["baseline_coverage_ratio"], 1.0);
    assert_eq!(metrics_res["total_investigations"], 1);
}
