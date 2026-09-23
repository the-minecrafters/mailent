use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dnssec::DnssecState;

/// Discovered Mail Exchange (MX) record for an email domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxRecord {
    pub domain: String,
    pub hostname: String,
    pub priority: u16,
    pub resolved_ips: Vec<String>,
    pub dnssec: DnssecState,
    #[serde(with = "time::serde::rfc3339")]
    pub first_seen: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_checked: OffsetDateTime,
}

/// DANE verification status comparing DNS TLSA records against observed TLS certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaneStatus {
    /// Certificate or public key matches TLSA record under a DNSSEC-secured zone.
    DaneMatch,
    /// Certificate or public key does NOT match TLSA record when DNSSEC is secure.
    DaneMismatch,
    /// DNSSEC validation is bogus or indeterminate, preventing trusted verification.
    DaneUnverifiable,
    /// TLSA record exists but DNSSEC is insecure (unsigned).
    TlsaWithoutSecureDnssec,
    /// No TLSA record published for endpoint.
    NoTlsa,
}

/// DANE TLSA record (RFC 6698 / RFC 7672) published at `_port._tcp.hostname`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsaRecord {
    pub domain: String,
    pub mx_host: String,
    pub port: u16,
    pub usage: u8,         // 0: PKIX-TA, 1: PKIX-EE, 2: DANE-TA, 3: DANE-EE
    pub selector: u8,      // 0: Full cert, 1: SubjectPublicKeyInfo
    pub matching_type: u8, // 0: Full data, 1: SHA-256, 2: SHA-512
    pub cert_association_data: String,
    pub dnssec: DnssecState,
    #[serde(with = "time::serde::rfc3339")]
    pub checked_at: OffsetDateTime,
}

/// Operating mode of an MTA-STS policy (RFC 8461).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MtaStsMode {
    None,
    Testing,
    Enforce,
}

/// Discovered and parsed MTA-STS policy (RFC 8461).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MtaStsPolicy {
    pub domain: String,
    pub version: String,
    pub mode: MtaStsMode,
    pub mx_patterns: Vec<String>,
    pub max_age_seconds: u32,
    pub dnssec: DnssecState,
    #[serde(with = "time::serde::rfc3339")]
    pub checked_at: OffsetDateTime,
}

/// Discovered TLS-RPT policy (RFC 8460) from `_smtp._tls.<domain>` TXT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsRptPolicy {
    pub domain: String,
    pub rua: Vec<String>, // reporting URIs (mailto: or https:)
    #[serde(with = "time::serde::rfc3339")]
    pub checked_at: OffsetDateTime,
}

/// Normalized aggregate TLS-RPT report (RFC 8460).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TlsRptAggregateReport {
    pub id: Uuid,
    pub organization_name: String,
    #[serde(with = "time::serde::rfc3339")]
    pub start_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub end_date: OffsetDateTime,
    pub policy_domain: String,
    pub successful_sessions: u64,
    pub failed_sessions: u64,
    pub failure_details: Vec<TlsRptFailureDetail>,
    #[serde(with = "time::serde::rfc3339")]
    pub imported_at: OffsetDateTime,
}

/// Fine-grained failure detail inside a TLS-RPT report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TlsRptFailureDetail {
    pub failure_type: String, // e.g. "certificate-expired", "starttls-not-supported", "validation-failure"
    pub receiving_mx: String,
    pub failed_count: u64,
    pub additional_info: Option<String>,
}

/// Certificate recorded in public Certificate Transparency (CT) logs for a domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CtCertificateRecord {
    pub sha256_fingerprint: String,
    pub domain: String,
    pub names: Vec<String>,
    pub issuer: String,
    #[serde(with = "time::serde::rfc3339")]
    pub not_before: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub not_after: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub ct_first_seen: OffsetDateTime,
    pub observed_on_network: bool,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub first_network_observation: Option<OffsetDateTime>,
}

/// Specific intelligence event observed in Certificate Transparency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CtIntelligenceEventKind {
    NewCtCertificate,
    UnexpectedCtIssuer,
    CtCertNowObservedOnMailServer,
}

/// Recorded CT intelligence event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CtIntelligenceEvent {
    pub id: Uuid,
    pub domain: String,
    pub fingerprint: String,
    pub kind: CtIntelligenceEventKind,
    pub title: String,
    pub description: String,
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
}

/// Refresh status and scheduled next check for external domain intelligence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntelligenceRefreshStatus {
    pub domain: String,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_checked: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub next_check: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_success: Option<OffsetDateTime>,
    pub last_error: Option<String>,
}
