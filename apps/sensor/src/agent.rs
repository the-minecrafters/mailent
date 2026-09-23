use mailent_domain::{
    EmailProtocol, NetworkFlow, NormalizedObservation, StartTlsState, TlsVersion,
};
use mailent_events::{DomainEvent, EventBus, EventEnvelope, InProcessEventBus};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::SensorConfig;

pub struct SensorAgent {
    pub config: SensorConfig,
    pub event_bus: InProcessEventBus,
}

impl SensorAgent {
    pub fn new(config: SensorConfig) -> Self {
        let event_bus = InProcessEventBus::new(config.buffer_capacity);
        Self { config, event_bus }
    }

    /// Emits a normalized observation into the sensor event pipeline.
    pub async fn emit_observation(
        &self,
        observation: NormalizedObservation,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let envelope = EventEnvelope::new(
            &self.config.sensor_id,
            "sensor.observations",
            DomainEvent::ObservationReceived(observation),
        );
        self.event_bus.publish(envelope).await?;
        Ok(())
    }

    /// Generates a synthetic test observation for safe local/dev verification.
    pub fn generate_dev_sample(&self) -> NormalizedObservation {
        NormalizedObservation {
            observation_id: Uuid::new_v4(),
            timestamp: OffsetDateTime::now_utc(),
            sensor_id: self.config.sensor_id.clone(),
            provenance: mailent_domain::ObservationProvenance {
                source: "synthetic".into(),
                parser: "mailent-fixture".into(),
                parser_version: "1".into(),
            },
            flow: NetworkFlow {
                src_ip: "10.0.1.5".to_string(),
                src_port: 54321,
                dst_ip: "10.0.2.25".to_string(),
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
        }
    }
}
