use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    cert::CertificateObservation,
    flow::NetworkFlow,
    protocol::{EmailProtocol, StartTlsState},
    tls::{CipherSuite, KeyExchange, TlsVersion},
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NormalizedObservation {
    pub observation_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub sensor_id: String,
    pub provenance: ObservationProvenance,
    pub flow: NetworkFlow,
    pub protocol: EmailProtocol,
    pub starttls_state: Option<StartTlsState>,
    pub tls_version: Option<TlsVersion>,
    pub cipher_suite: Option<CipherSuite>,
    pub key_exchange: Option<KeyExchange>,
    pub certificate: Option<CertificateObservation>,
    #[serde(default)]
    pub capture: Option<crate::CaptureEvidence>,
    pub raw_metadata: Option<serde_json::Value>,
}

/// Origin of the supplied metadata; this is evidence, never an inferred verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationProvenance {
    pub source: String,
    pub parser: String,
    pub parser_version: String,
}

impl NormalizedObservation {
    pub fn validate(&self) -> Result<(), crate::DomainError> {
        let invalid = |message: &str| crate::DomainError::InvalidObservation(message.into());
        if self.observation_id.is_nil() || self.sensor_id.trim().is_empty() {
            return Err(invalid("observation_id and sensor_id are required"));
        }
        for ip in [&self.flow.src_ip, &self.flow.dst_ip] {
            if ip.parse::<std::net::IpAddr>().is_err() {
                return Err(invalid("flow addresses must be IP addresses"));
            }
        }
        if self.flow.src_port == 0 || self.flow.dst_port == 0 {
            return Err(invalid("flow ports must be nonzero"));
        }
        if [
            &self.provenance.source,
            &self.provenance.parser,
            &self.provenance.parser_version,
        ]
        .iter()
        .any(|value| value.trim().is_empty())
        {
            return Err(invalid("source and parser provenance are required"));
        }
        if let Some(cert) = &self.certificate {
            let fingerprint = &cert.reference.sha256_fingerprint;
            if fingerprint.len() != 64 || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(invalid(
                    "certificate fingerprint must be a SHA-256 hex digest",
                ));
            }
            if cert.validity.not_before > cert.validity.not_after {
                return Err(invalid("certificate validity range is reversed"));
            }
        }
        Ok(())
    }
}
