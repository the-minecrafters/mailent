use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::cert_crypto::CertificateCryptoDetails;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CertificateReference {
    pub sha256_fingerprint: String,
    pub subject: String,
    pub issuer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValidityPeriod {
    #[serde(with = "time::serde::rfc3339")]
    pub not_before: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub not_after: OffsetDateTime,
}

impl ValidityPeriod {
    pub fn is_expired_at(&self, at: OffsetDateTime) -> bool {
        at > self.not_after
    }

    pub fn is_not_yet_valid_at(&self, at: OffsetDateTime) -> bool {
        at < self.not_before
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateObservation {
    pub reference: CertificateReference,
    pub validity: ValidityPeriod,
    pub is_self_signed: Option<bool>,
    pub san: Vec<String>,
    /// Extended crypto details; `None` when the evidence path could not
    /// extract them (they are then reported as unavailable, never guessed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crypto_details: Option<CertificateCryptoDetails>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateRecord {
    pub sha256_fingerprint: String,
    pub subject: String,
    pub issuer: String,
    pub sans: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub not_before: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub not_after: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub first_seen: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen: OffsetDateTime,
    pub associated_asset_ids: Vec<uuid::Uuid>,
}
