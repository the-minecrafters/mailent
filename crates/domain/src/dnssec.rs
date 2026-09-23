use serde::{Deserialize, Serialize};

/// Cryptographic validation state of DNS resource records via DNSSEC (RFC 4033 / RFC 4034 / RFC 4035).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnssecState {
    /// DNSSEC signatures (RRSIG) valid and validated up to trusted root anchor.
    Secure,
    /// Zone or record is unsigned; no DNSSEC validation is asserted.
    Insecure,
    /// DNSSEC signatures failed validation (e.g. signature expired or key mismatch).
    Bogus,
    /// Validation could not be conclusively determined (e.g. resolver network error).
    Indeterminate,
}
