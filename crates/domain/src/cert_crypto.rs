//! Extended X.509 cryptographic details observed from a presented certificate.
//!
//! Everything here is an observed fact extracted from the certificate bytes
//! (or, for chain validation, from an active probe). When a field cannot be
//! extracted from the available evidence it is `None` — never guessed — and
//! reports render it as "unavailable".
use serde::{Deserialize, Serialize};

/// Hash of the raw SubjectPublicKeyInfo (SPKI) DER bytes.
/// Corresponds to DANE "full certificate" vs "SPKI" selector material.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKeyDetails {
    /// e.g. "RSA", "EC", "Ed25519"; `None` when the algorithm is unparseable.
    pub algorithm: Option<String>,
    /// RSA modulus size in bits, when applicable.
    pub rsa_bits: Option<u16>,
    /// Named EC curve (e.g. "secp256r1", "X25519"), when applicable.
    pub ec_curve: Option<String>,
    /// SPKI SHA-256 hex digest when raw SPKI DER is available.
    pub spki_sha256: Option<String>,
}

/// Deterministic chain + trust validation result produced by an active probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainValidation {
    /// Chain verified to a trust anchor on the validating host.
    Verified,
    /// Validation explicitly failed (untrusted/self-signed/broken chain).
    Failed,
    /// No active validation was performed; the result is genuinely unknown.
    NotVerified,
}

impl std::fmt::Display for ChainValidation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Verified => write!(f, "verified"),
            Self::Failed => write!(f, "failed"),
            Self::NotVerified => write!(f, "not_verified"),
        }
    }
}

/// X.509 v3 extension names observed on the certificate (deterministic order).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateExtensions {
    pub basic_constraints: Option<String>,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
}

/// Crypto-level details for one observed certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateCryptoDetails {
    /// Certificate signature algorithm, e.g. "sha256WithRSAEncryption" or
    /// "ecdsa-with-SHA256"; `None` when unavailable from the evidence.
    pub signature_algorithm: Option<String>,
    /// Public key material details.
    pub public_key: PublicKeyDetails,
    /// Deterministic chain/trust validation outcome (active probe evidence).
    pub chain_validation: ChainValidation,
    /// Chain length observed by an active probe (1 = leaf only / trust on first).
    pub chain_length: Option<u8>,
    /// X.509 extensions of forensic interest.
    pub extensions: CertificateExtensions,
}

impl CertificateCryptoDetails {
    /// Honest rendering helper: `None` fields are reported as unavailable.
    pub fn signature_algorithm_display(&self) -> String {
        self.signature_algorithm
            .clone()
            .unwrap_or_else(|| "unavailable".to_string())
    }

    /// Human summary of the public key: algorithm plus size/curve where known.
    pub fn public_key_display(&self) -> String {
        let pk = &self.public_key;
        match (&pk.algorithm, pk.rsa_bits, &pk.ec_curve) {
            (Some(alg), Some(bits), _) => format!("{alg} {bits} bits"),
            (Some(alg), None, Some(curve)) => format!("{alg} curve {curve}"),
            (Some(alg), None, None) => alg.clone(),
            (None, _, _) => "unavailable".to_string(),
        }
    }
}
