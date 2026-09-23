use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

pub const DEFAULT_ORG_ID: Uuid = Uuid::from_u128(1); // 00000000-0000-0000-0000-000000000001
pub const DEFAULT_ORG_NAME: &str = "Acme Inc";
pub const DEFAULT_ORG_SLUG: &str = "acme-inc";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl Default for Organization {
    fn default() -> Self {
        Self {
            id: DEFAULT_ORG_ID,
            name: DEFAULT_ORG_NAME.to_string(),
            slug: DEFAULT_ORG_SLUG.to_string(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationMember {
    pub organization_id: Uuid,
    pub user_id: String,
    pub role: String, // "admin", "member"
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}
