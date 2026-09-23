use mailent_domain::{DaneStatus, DnssecState, TlsaRecord};
use sha2::{Digest, Sha256, Sha512};
use time::OffsetDateTime;

use crate::IntegrationError;

/// Parses a TLSA record from DNS RDATA (RFC 6698).
///
/// Typical format: `<usage> <selector> <matching_type> <association_data>`
/// e.g. `3 1 1 e714bc098be8370c1c82fa7d2cdaf60ca8534368198de0527ce887f5a84f99c6`
pub fn parse_tlsa_record(
    domain: &str,
    mx_host: &str,
    port: u16,
    rdata: &str,
    dnssec: DnssecState,
) -> Result<TlsaRecord, IntegrationError> {
    let parts: Vec<&str> = rdata.split_whitespace().collect();
    if parts.len() < 4 {
        return Err(IntegrationError::Format(format!(
            "malformed TLSA record, expected at least 4 fields, got: {rdata}"
        )));
    }

    let usage: u8 = parts[0].parse().map_err(|e| {
        IntegrationError::Format(format!("invalid TLSA usage field '{}': {e}", parts[0]))
    })?;
    let selector: u8 = parts[1].parse().map_err(|e| {
        IntegrationError::Format(format!("invalid TLSA selector field '{}': {e}", parts[1]))
    })?;
    let matching_type: u8 = parts[2].parse().map_err(|e| {
        IntegrationError::Format(format!(
            "invalid TLSA matching_type field '{}': {e}",
            parts[2]
        ))
    })?;

    // The remaining parts comprise the association data (may be space-separated hex in raw records)
    let cert_association_data = parts[3..].join("").to_ascii_lowercase();

    Ok(TlsaRecord {
        domain: domain.to_string(),
        mx_host: mx_host.to_string(),
        port,
        usage,
        selector,
        matching_type,
        cert_association_data,
        dnssec,
        checked_at: OffsetDateTime::now_utc(),
    })
}

/// Evaluates a TLSA record against observed certificate data and DNSSEC status.
pub use validate_dane as validate_tlsa;

pub fn validate_dane(
    tlsa: &TlsaRecord,
    cert_sha256_fingerprint: &str,
    cert_der_bytes: Option<&[u8]>,
    spki_der_bytes: Option<&[u8]>,
) -> DaneStatus {
    // 1. Check DNSSEC security first (RFC 7672 Section 2.1)
    match tlsa.dnssec {
        DnssecState::Bogus | DnssecState::Indeterminate => {
            return DaneStatus::DaneUnverifiable;
        }
        DnssecState::Insecure => {
            return DaneStatus::TlsaWithoutSecureDnssec;
        }
        DnssecState::Secure => {}
    }

    let target_hex = tlsa
        .cert_association_data
        .to_ascii_lowercase()
        .replace([':', ' ', '-'], "");

    // 2. Evaluate based on selector & matching type
    let matches = match (tlsa.selector, tlsa.matching_type) {
        // Selector 0 (Full Certificate), Matching 1 (SHA-256)
        (0, 1) => {
            let fp_clean = cert_sha256_fingerprint
                .to_ascii_lowercase()
                .replace([':', ' ', '-'], "");
            fp_clean == target_hex
        }
        // Selector 0 (Full Certificate), Matching 0 (Exact Match)
        (0, 0) => {
            if let Some(der) = cert_der_bytes {
                let der_hex = hex::encode(der);
                der_hex.to_ascii_lowercase() == target_hex
            } else {
                false
            }
        }
        // Selector 0 (Full Certificate), Matching 2 (SHA-512)
        (0, 2) => {
            if let Some(der) = cert_der_bytes {
                let mut hasher = Sha512::new();
                hasher.update(der);
                let hash_hex = hex::encode(&hasher.finalize());
                hash_hex.to_ascii_lowercase() == target_hex
            } else {
                false
            }
        }
        // Selector 1 (SubjectPublicKeyInfo), Matching 1 (SHA-256)
        (1, 1) => {
            if let Some(spki) = spki_der_bytes {
                let mut hasher = Sha256::new();
                hasher.update(spki);
                let hash_hex = hex::encode(&hasher.finalize());
                hash_hex.to_ascii_lowercase() == target_hex
            } else {
                false
            }
        }
        // Selector 1 (SubjectPublicKeyInfo), Matching 0 (Exact Match)
        (1, 0) => {
            if let Some(spki) = spki_der_bytes {
                let spki_hex = hex::encode(spki);
                spki_hex.to_ascii_lowercase() == target_hex
            } else {
                false
            }
        }
        _ => false,
    };

    if matches {
        DaneStatus::DaneMatch
    } else {
        DaneStatus::DaneMismatch
    }
}

// Minimal hex encoding helper without external hex crate
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_and_validate_tlsa_match() {
        let fp = "e714bc098be8370c1c82fa7d2cdaf60ca8534368198de0527ce887f5a84f99c6";
        let rdata = format!("3 0 1 {fp}");
        let tlsa = parse_tlsa_record(
            "example.com",
            "mail.example.com",
            25,
            &rdata,
            DnssecState::Secure,
        )
        .unwrap();

        assert_eq!(tlsa.usage, 3);
        assert_eq!(tlsa.selector, 0);
        assert_eq!(tlsa.matching_type, 1);
        assert_eq!(tlsa.cert_association_data, fp);

        let status = validate_tlsa(&tlsa, fp, None, None);
        assert_eq!(status, DaneStatus::DaneMatch);
    }

    #[test]
    fn test_tlsa_mismatch() {
        let expected_fp = "e714bc098be8370c1c82fa7d2cdaf60ca8534368198de0527ce887f5a84f99c6";
        let different_fp = "1111111111111111111111111111111111111111111111111111111111111111";
        let rdata = format!("3 0 1 {expected_fp}");
        let tlsa = parse_tlsa_record(
            "example.com",
            "mail.example.com",
            25,
            &rdata,
            DnssecState::Secure,
        )
        .unwrap();

        let status = validate_tlsa(&tlsa, different_fp, None, None);
        assert_eq!(status, DaneStatus::DaneMismatch);
    }

    #[test]
    fn test_tlsa_insecure_dnssec() {
        let fp = "e714bc098be8370c1c82fa7d2cdaf60ca8534368198de0527ce887f5a84f99c6";
        let rdata = format!("3 0 1 {fp}");
        let tlsa = parse_tlsa_record(
            "example.com",
            "mail.example.com",
            25,
            &rdata,
            DnssecState::Insecure,
        )
        .unwrap();

        let status = validate_tlsa(&tlsa, fp, None, None);
        assert_eq!(status, DaneStatus::TlsaWithoutSecureDnssec);
    }
}
