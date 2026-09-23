use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub registered_by_user_id: Option<String>,
    pub name: String,
    pub hostname: String,
    pub platform: String,
    pub architecture: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub agent_enabled: bool,
    #[serde(default)]
    pub agent_status: Option<String>,
    #[serde(default)]
    pub current_job_id: Option<Uuid>,
    #[serde(default)]
    pub completed_jobs_count: u32,
}

impl Device {
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuthorizationChallenge {
    pub code: String,
    pub device_name: String,
    pub hostname: String,
    pub platform: String,
    pub architecture: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub authorized_at: Option<OffsetDateTime>,
    pub authorized_by_user_id: Option<String>,
    pub organization_id: Option<Uuid>,
    pub issued_token: Option<String>,
    pub device_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceTokenRecord {
    pub token_hash: String,
    pub device_id: Uuid,
    pub organization_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_used_at: OffsetDateTime,
}
