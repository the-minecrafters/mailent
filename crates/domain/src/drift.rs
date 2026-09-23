use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriftKind {
    NewTlsVersion,
    NewCipherSuite,
    KeyExchangeChanged,
    ForwardSecrecyLost,
    CertificateChanged,
    NewCertificateIssuer,
    NewEndpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftEvent {
    pub id: Uuid,
    pub asset_id: Uuid,
    pub kind: DriftKind,
    pub title: String,
    pub description: String,
    pub previous_value: Option<String>,
    pub new_value: String,
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
    pub session_id: Option<Uuid>,
}
