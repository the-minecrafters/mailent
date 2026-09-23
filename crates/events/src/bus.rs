use async_trait::async_trait;
use tokio::sync::broadcast;

use crate::{
    envelope::{DomainEvent, EventEnvelope},
    error::EventBusError,
};

#[async_trait]
pub trait EventBus: Send + Sync {
    async fn publish(&self, event: EventEnvelope<DomainEvent>) -> Result<(), EventBusError>;
}

/// Single-node in-process event bus using a bounded Tokio broadcast channel.
/// For notifications only: slow consumers receive a lag error. This is not durable ingestion.
#[derive(Clone)]
pub struct InProcessEventBus {
    sender: broadcast::Sender<EventEnvelope<DomainEvent>>,
}

impl InProcessEventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EventEnvelope<DomainEvent>> {
        self.sender.subscribe()
    }
}

impl Default for InProcessEventBus {
    fn default() -> Self {
        Self::new(1024)
    }
}

#[async_trait]
impl EventBus for InProcessEventBus {
    async fn publish(&self, event: EventEnvelope<DomainEvent>) -> Result<(), EventBusError> {
        self.sender
            .send(event)
            .map_err(|_| EventBusError::ChannelClosed)?;
        Ok(())
    }
}

/// Boundary configuration for future distributed Redpanda / Kafka streaming.
/// Kept as an explicit configuration boundary without requiring external brokers today.
#[derive(Debug, Clone)]
pub struct RedpandaEventBusConfig {
    pub brokers: Vec<String>,
    pub client_id: String,
    pub default_topic: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailent_domain::{
        EmailProtocol, NetworkFlow, NormalizedObservation, StartTlsState, TlsVersion,
    };
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_in_process_event_bus_publish_and_receive() {
        let bus = InProcessEventBus::new(32);
        let mut rx = bus.subscribe();

        let obs = NormalizedObservation {
            observation_id: Uuid::new_v4(),
            timestamp: OffsetDateTime::now_utc(),
            sensor_id: "test-sensor".to_string(),
            provenance: mailent_domain::ObservationProvenance {
                source: "synthetic".into(),
                parser: "mailent-fixture".into(),
                parser_version: "1".into(),
            },
            flow: NetworkFlow {
                src_ip: "10.0.0.1".to_string(),
                src_port: 1234,
                dst_ip: "10.0.0.2".to_string(),
                dst_port: 25,
            },
            protocol: EmailProtocol::Smtp,
            starttls_state: Some(StartTlsState::AdvertisedAndUsed),
            tls_version: Some(TlsVersion::Tls13),
            cipher_suite: None,
            key_exchange: None,
            certificate: None,
            capture: None,
            raw_metadata: None,
        };

        let envelope = EventEnvelope::new(
            "test_source",
            "sensor.observations",
            DomainEvent::ObservationReceived(obs.clone()),
        );

        bus.publish(envelope.clone())
            .await
            .expect("publish should succeed");

        let received = rx.recv().await.expect("receive should succeed");
        assert_eq!(received.event_id, envelope.event_id);
        assert_eq!(received.topic, "sensor.observations");
        drop(rx);
        assert!(matches!(
            bus.publish(envelope).await,
            Err(EventBusError::ChannelClosed)
        ));
    }
}
