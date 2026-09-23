use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    cert::CertificateObservation,
    flow::NetworkFlow,
    observation::NormalizedObservation,
    protocol::{EmailProtocol, StartTlsState},
    tls::{CipherSuite, KeyExchange, TlsVersion},
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmailSession {
    pub session_id: Uuid,
    pub sensor_id: String,
    pub provenance: crate::ObservationProvenance,
    pub flow: NetworkFlow,
    pub protocol: EmailProtocol,
    pub starttls_state: Option<StartTlsState>,
    pub tls_version: Option<TlsVersion>,
    pub cipher_suite: Option<CipherSuite>,
    pub key_exchange: Option<KeyExchange>,
    pub certificate: Option<CertificateObservation>,
    #[serde(default)]
    pub capture: Option<crate::CaptureEvidence>,
    #[serde(with = "time::serde::rfc3339")]
    pub first_seen: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen: OffsetDateTime,
}

impl From<&NormalizedObservation> for EmailSession {
    fn from(obs: &NormalizedObservation) -> Self {
        Self {
            session_id: obs.observation_id,
            sensor_id: obs.sensor_id.clone(),
            provenance: obs.provenance.clone(),
            flow: obs.flow.clone(),
            protocol: obs.protocol,
            starttls_state: obs.starttls_state,
            tls_version: obs.tls_version.clone(),
            cipher_suite: obs.cipher_suite.clone(),
            key_exchange: obs.key_exchange.clone(),
            certificate: obs.certificate.clone(),
            capture: obs.capture.clone(),
            first_seen: obs.timestamp,
            last_seen: obs.timestamp,
        }
    }
}
