use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SensorStatus {
    Online,
    Stale,
    Offline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorRecord {
    pub sensor_id: String,
    pub site_id: String,
    pub hostname: String,
    pub version: String,
    pub mode: String,
    pub interface: Option<String>,
    pub status: SensorStatus,
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub registered_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorHeartbeat {
    pub sensor_id: String,
    pub site_id: String,
    pub hostname: String,
    pub version: String,
    pub mode: String,
    pub interface: Option<String>,
    #[serde(default)]
    pub observations_processed: u64,
    #[serde(default)]
    pub observations_spooled: u64,
    #[serde(default)]
    pub observations_dropped: u64,
}
