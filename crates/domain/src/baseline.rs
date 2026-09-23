use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

/// Statistical behavioral baseline constructed per asset over historical session windows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssetBaseline {
    pub asset_id: Uuid,
    pub sample_count: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub window_start: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub window_end: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub coverage: f32, // 0.0 .. 1.0 (proportion of observed sessions covered)
    pub tls_version_distribution: HashMap<String, f32>,
    pub cipher_distribution: HashMap<String, f32>,
    pub key_exchange_distribution: HashMap<String, f32>,
    pub certificate_fingerprints: Vec<String>,
    pub certificate_issuers: Vec<String>,
    pub starttls_success_rate: f32,
    pub handshake_failure_rate: f32,
    pub peer_set: Vec<String>,
    pub ports: Vec<u16>,
    pub session_frequency_per_hour: f32,
}

/// Anomaly candidate indicating observed behavior deviates significantly from established baseline.
/// Note: An anomaly represents unusual or changed behavior, distinct from a deterministic policy finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnomalySignal {
    pub id: Uuid,
    pub asset_id: Uuid,
    pub signal: String, // e.g. "UnseenTlsVersion", "RareCipher", "StarttlsSuccessRateDrop", "HandshakeFailureSpike", "NewDaneMismatch", "MtaStsMismatch", "TlsRptFailureSpike", "InternalExternalInconsistency"
    pub title: String,
    pub current_value: String,
    pub baseline_value: String,
    pub deviation: f32,
    pub confidence: f32,
    pub evidence: String,
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
}
