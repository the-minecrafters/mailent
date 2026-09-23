#[path = "../../../tests/support/databases.rs"]
mod databases;
use mailent_domain::{
    Asset, AssetEndpoint, AssetIdentity, CertificateRecord, DriftEvent, DriftKind, EmailProtocol,
    Finding, FindingCategory, FindingSeverity, NetworkFlow, NormalizedObservation,
    ObservationProvenance, SensorHeartbeat, SensorStatus, TlsVersion,
};
use mailent_storage::{
    clickhouse::ClickHouseStorage,
    postgres::PostgresStorage,
    repository::{
        AssetRepository, CertificateRepository, FindingRepository, ObservationRepository,
        SensorRepository,
    },
};
use time::OffsetDateTime;
use uuid::Uuid;

#[tokio::test]
async fn test_postgres_integration() {
    let Some(db) = databases::TestDatabases::start().await else {
        return;
    };
    let storage = PostgresStorage::connect(&db.postgres_url)
        .await
        .expect("isolated PostgreSQL migration");
    // 1. Asset test
    let asset_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let test_ip = format!("192.0.2.{}", (now.unix_timestamp_nanos().abs() % 200) + 10);
    let asset = Asset {
        id: asset_id,
        primary_name: Some("mail.example.com".to_string()),
        addresses: vec![test_ip.clone()],
        hostnames: vec!["mail.example.com".to_string()],
        identities: vec![AssetIdentity {
            kind: "domain".to_string(),
            value: "example.com".to_string(),
            first_seen: now,
            last_seen: now,
        }],
        endpoints: vec![AssetEndpoint {
            protocol: EmailProtocol::Smtp,
            port: 25,
            tls_versions: vec![TlsVersion::Tls13],
            cipher_suites: vec!["TLS_AES_256_GCM_SHA384".to_string()],
            first_seen: now,
            last_seen: now,
        }],
        tls_versions: vec![TlsVersion::Tls13],
        cipher_suites: vec!["TLS_AES_256_GCM_SHA384".to_string()],
        certificate_fingerprints: vec!["sha256:11223344556677889900aabbccddeeff".to_string()],
        active_findings_count: 0,
        first_seen: now,
        last_seen: now,
    };

    AssetRepository::upsert(&storage, asset.clone())
        .await
        .expect("upsert asset");

    let found = AssetRepository::find_by_id(&storage, asset_id)
        .await
        .expect("find by id")
        .expect("asset exists");
    assert_eq!(found.primary_name, Some("mail.example.com".to_string()));
    assert_eq!(found.addresses, vec![test_ip.clone()]);
    assert_eq!(found.hostnames, vec!["mail.example.com".to_string()]);

    let found_by_addr = AssetRepository::find_by_address_or_identity(&storage, &test_ip)
        .await
        .expect("find by addr")
        .expect("found");
    assert_eq!(found_by_addr.id, asset_id);

    // 2. Certificate test
    let cert = CertificateRecord {
        sha256_fingerprint: "sha256:11223344556677889900aabbccddeeff".to_string(),
        subject: "CN=mail.example.com".to_string(),
        issuer: "CN=Let's Encrypt".to_string(),
        sans: vec!["mail.example.com".to_string()],
        not_before: now,
        not_after: now + time::Duration::days(90),
        first_seen: now,
        last_seen: now,
        associated_asset_ids: vec![asset_id],
    };
    CertificateRepository::save(&storage, cert.clone())
        .await
        .expect("save cert");
    let found_cert = CertificateRepository::find_by_fingerprint(
        &storage,
        "sha256:11223344556677889900aabbccddeeff",
    )
    .await
    .expect("find cert")
    .expect("cert exists");
    assert_eq!(found_cert.subject, "CN=mail.example.com");

    // 3. Drift event test
    let drift = DriftEvent {
        id: Uuid::new_v4(),
        asset_id,
        kind: DriftKind::NewTlsVersion,
        title: "New TLS Version Observed".to_string(),
        description: "Observed TLS 1.3 for the first time".to_string(),
        previous_value: Some("TLS 1.2".to_string()),
        new_value: "TLS 1.3".to_string(),
        session_id: Some(Uuid::new_v4()),
        observed_at: now,
    };
    AssetRepository::save_drift_event(&storage, drift.clone())
        .await
        .expect("save drift event");
    let drifts = AssetRepository::list_drift_events(&storage, Some(asset_id), 10)
        .await
        .expect("list drift events");
    assert_eq!(drifts.len(), 1);
    assert_eq!(drifts[0].kind, DriftKind::NewTlsVersion);

    // 4. Sensor heartbeat test
    let hb = SensorHeartbeat {
        sensor_id: "test-sensor-01".to_string(),
        site_id: "site-alpha".to_string(),
        hostname: "sensor-host-1".to_string(),
        version: "0.1.0".to_string(),
        mode: "pcap_reader".to_string(),
        interface: Some("eth0".to_string()),
        observations_processed: 42,
        observations_spooled: 0,
        observations_dropped: 0,
    };
    SensorRepository::record_heartbeat(&storage, hb)
        .await
        .expect("record heartbeat");
    let sensors = SensorRepository::list_sensors(&storage)
        .await
        .expect("list sensors");
    assert_eq!(sensors.len(), 1);
    assert_eq!(sensors[0].sensor_id, "test-sensor-01");
    assert_eq!(sensors[0].status, SensorStatus::Online);

    // 5. Finding test
    let finding = Finding {
        id: Uuid::new_v4(),
        rule_id: "TLS-001".to_string(),
        policy_name: "Modern Transport".to_string(),
        policy_version: "1.0".to_string(),
        reference: "RFC 8996".to_string(),
        category: FindingCategory::TlsConfiguration,
        severity: FindingSeverity::High,
        title: "Deprecated TLS Version".to_string(),
        description: "TLS 1.0 was detected".to_string(),
        remediation: "Upgrade to TLS 1.3".to_string(),
        evidence: vec![],
        first_seen: now,
        last_seen: now,
        affected_count: 1,
    };
    FindingRepository::save(&storage, finding.clone())
        .await
        .expect("save finding");
    let f_found = FindingRepository::find_by_id(&storage, finding.id)
        .await
        .expect("find finding")
        .expect("finding exists");
    assert_eq!(f_found.rule_id, "TLS-001");

    // 6. Intelligence test
    use mailent_domain::{
        AnomalySignal, AssetBaseline, DecisionRecord, DecisionResult, DnssecState, Investigation,
        InvestigationStatus, MtaStsMode, MtaStsPolicy, MxRecord, PriorityLevel, RiskLevel,
    };
    use mailent_storage::repository::{
        BaselineRepository, DecisionRepository, IntelligenceRepository, InvestigationRepository,
    };

    let domain = "example.com";
    let mx = MxRecord {
        domain: domain.to_string(),
        hostname: "mail.example.com".to_string(),
        priority: 10,
        resolved_ips: vec!["192.0.2.1".to_string()],
        dnssec: DnssecState::Secure,
        first_seen: now,
        last_checked: now,
    };
    IntelligenceRepository::save_mx_records(&storage, domain, std::slice::from_ref(&mx))
        .await
        .expect("save mx");
    let mx_list = IntelligenceRepository::get_mx_records(&storage, domain)
        .await
        .expect("get mx");
    assert_eq!(mx_list.len(), 1);
    assert_eq!(mx_list[0].hostname, "mail.example.com");

    let mta_sts = MtaStsPolicy {
        domain: domain.to_string(),
        version: "STSv1".to_string(),
        mode: MtaStsMode::Enforce,
        mx_patterns: vec!["*.example.com".to_string()],
        max_age_seconds: 604800,
        dnssec: DnssecState::Secure,
        checked_at: now,
    };
    IntelligenceRepository::save_mta_sts_policy(&storage, &mta_sts)
        .await
        .expect("save mta sts");
    let fetched_mta_sts = IntelligenceRepository::get_mta_sts_policy(&storage, domain)
        .await
        .expect("get mta sts")
        .expect("mta sts exists");
    assert_eq!(fetched_mta_sts.mode, MtaStsMode::Enforce);

    // 7. Baseline and Anomaly test
    let baseline = AssetBaseline {
        asset_id,
        sample_count: 50,
        window_start: now - time::Duration::days(7),
        window_end: now,
        generated_at: now,
        coverage: 1.0,
        tls_version_distribution: std::collections::HashMap::from([("TLSv1.3".to_string(), 1.0)]),
        cipher_distribution: std::collections::HashMap::new(),
        key_exchange_distribution: std::collections::HashMap::new(),
        certificate_fingerprints: vec!["sha256:112233".to_string()],
        certificate_issuers: vec!["DigiCert".to_string()],
        starttls_success_rate: 1.0,
        handshake_failure_rate: 0.0,
        peer_set: vec!["10.0.0.1".to_string()],
        ports: vec![25],
        session_frequency_per_hour: 5.0,
    };
    BaselineRepository::save_baseline(&storage, &baseline)
        .await
        .expect("save baseline");
    let fetched_bl = BaselineRepository::get_baseline(&storage, asset_id)
        .await
        .expect("get baseline")
        .expect("baseline exists");
    assert_eq!(fetched_bl.sample_count, 50);

    let anomaly = AnomalySignal {
        id: Uuid::new_v4(),
        asset_id,
        signal: "UnseenTlsVersion".to_string(),
        title: "Unseen TLS Version".to_string(),
        current_value: "TLSv1.0".to_string(),
        baseline_value: "TLSv1.3".to_string(),
        deviation: 1.0,
        confidence: 0.95,
        evidence: "Legacy downgrade".to_string(),
        observed_at: now,
    };
    BaselineRepository::save_anomaly(&storage, &anomaly)
        .await
        .expect("save anomaly");
    let anomalies = BaselineRepository::list_anomalies(&storage, Some(asset_id), 10)
        .await
        .expect("list anomalies");
    assert_eq!(anomalies.len(), 1);
    assert_eq!(anomalies[0].signal, "UnseenTlsVersion");

    // 8. Investigation test
    let investigation = Investigation {
        id: Uuid::new_v4(),
        asset_id,
        title: "Potential Downgrade Attack".to_string(),
        summary: "Downgrade observed with active MTA-STS enforcement".to_string(),
        status: InvestigationStatus::Open,
        risk: RiskLevel::Critical,
        priority: PriorityLevel::Immediate,
        finding_ids: vec!["TLS-001".to_string()],
        drift_event_ids: vec![drift.id],
        anomaly_ids: vec![anomaly.id],
        external_intelligence: serde_json::json!({"mta_sts": "enforce"}),
        jev_decision: Some(DecisionResult {
            risk: RiskLevel::Critical,
            anomalous: true,
            human_review: true,
            priority: PriorityLevel::Immediate,
            confidence: 0.98,
            provider_info: "jev:openjev-0.1".to_string(),
            reasons: vec!["Active MITM indicator".to_string()],
        }),
        first_observed: now,
        last_observed: now,
    };
    InvestigationRepository::save(&storage, &investigation)
        .await
        .expect("save investigation");
    let fetched_inv = InvestigationRepository::find_by_id(&storage, investigation.id)
        .await
        .expect("find investigation")
        .expect("investigation exists");
    assert_eq!(fetched_inv.risk, RiskLevel::Critical);
    assert_eq!(fetched_inv.priority, PriorityLevel::Immediate);

    // 9. Decision Record test
    let dec_record = DecisionRecord {
        id: Uuid::new_v4(),
        session_id: Some(Uuid::new_v4()),
        asset_id: Some(asset_id),
        provider: "jev".to_string(),
        model: "openjev-0.1".to_string(),
        decision: DecisionResult {
            risk: RiskLevel::Critical,
            anomalous: true,
            human_review: true,
            priority: PriorityLevel::Immediate,
            confidence: 0.98,
            provider_info: "jev:openjev-0.1".to_string(),
            reasons: vec!["Downgrade anomaly".to_string()],
        },
        latency_ms: 245,
        created_at: now,
    };
    DecisionRepository::save_record(&storage, &dec_record)
        .await
        .expect("save decision record");
    let decs = DecisionRepository::list_recent(&storage, 10)
        .await
        .expect("list decision records");
    assert!(!decs.is_empty());
    assert_eq!(decs[0].provider, "jev");
    storage.pool().close().await;
    db.finish().await;
}

#[tokio::test]
async fn test_clickhouse_integration() {
    let Some(db) = databases::TestDatabases::start().await else {
        return;
    };
    let storage = ClickHouseStorage::connect(&db.clickhouse_url, &db.clickhouse_database)
        .await
        .expect("isolated ClickHouse migration");

    let now = OffsetDateTime::now_utc();
    let obs_id = Uuid::new_v4();
    let obs = NormalizedObservation {
        observation_id: obs_id,
        timestamp: now,
        sensor_id: "sensor-test".to_string(),
        provenance: ObservationProvenance {
            source: "zeek".to_string(),
            parser: "zeek-tsv".to_string(),
            parser_version: "0.1.0".to_string(),
        },
        flow: NetworkFlow {
            src_ip: "192.168.1.50".to_string(),
            src_port: 45678,
            dst_ip: "192.168.1.1".to_string(),
            dst_port: 25,
        },
        protocol: EmailProtocol::Smtp,
        starttls_state: None,
        tls_version: Some(TlsVersion::Tls13),
        cipher_suite: None,
        key_exchange: None,
        certificate: None,
        capture: None,
        raw_metadata: None,
    };

    ObservationRepository::save(&storage, obs)
        .await
        .expect("save observation to ClickHouse");
    let found = ObservationRepository::find_by_id(&storage, obs_id)
        .await
        .expect("query observation")
        .expect("observation found");
    assert_eq!(found.observation_id, obs_id);
    assert_eq!(found.protocol, EmailProtocol::Smtp);
    db.finish().await;
}
