use mailent_core::{AppState, integrations::dispatch_to_destination};
use mailent_domain::{
    IntegrationConfig, IntegrationEventPayload, IntegrationEventType, IntegrationKind,
};
use time::OffsetDateTime;
use uuid::Uuid;

#[tokio::test]
async fn syslog_test_reaches_the_configured_receiver() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let now = OffsetDateTime::now_utc();
    let state = AppState::new();
    let config = IntegrationConfig {
        id: Uuid::new_v4(),
        name: "Local receiver".into(),
        kind: IntegrationKind::Syslog,
        destination: format!("udp://{}", socket.local_addr().unwrap()),
        event_types: vec![IntegrationEventType::VerificationCompleted],
        enabled: true,
        auth_header: None,
        last_delivery_at: None,
        last_status_code: None,
        last_error: None,
        created_at: now,
        updated_at: now,
    };
    state.integrations.save(&config).await.unwrap();
    let event = IntegrationEventPayload {
        event_id: Uuid::new_v4(),
        event_type: IntegrationEventType::VerificationCompleted,
        title: "Delivery check".into(),
        summary: "Confirmed locally".into(),
        asset_id: None,
        asset_name: None,
        investigation_id: None,
        finding_id: None,
        probe_id: None,
        details: serde_json::Value::Null,
        timestamp: now,
    };
    dispatch_to_destination(&state, &config, &event)
        .await
        .unwrap();
    let mut buffer = [0; 8192];
    let count = tokio::time::timeout(std::time::Duration::from_secs(1), socket.recv(&mut buffer))
        .await
        .expect("Syslog must actually send the event")
        .unwrap();
    assert!(String::from_utf8_lossy(&buffer[..count]).contains("Delivery check"));
}
