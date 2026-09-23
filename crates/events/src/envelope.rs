use mailent_domain::{EmailSession, Finding, NormalizedObservation};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum DomainEvent {
    ObservationReceived(NormalizedObservation),
    SessionCorrelated(EmailSession),
    FindingGenerated(Finding),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventEnvelope<T = DomainEvent> {
    pub event_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub source: String,
    pub topic: String,
    pub payload: T,
}

impl<T> EventEnvelope<T> {
    pub fn new(source: impl Into<String>, topic: impl Into<String>, payload: T) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            timestamp: OffsetDateTime::now_utc(),
            source: source.into(),
            topic: topic.into(),
            payload,
        }
    }
}
