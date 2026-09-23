use mailent_domain::{CertificateObservation, DnssecState, EmailSession, MtaStsMode, MtaStsPolicy};
use time::OffsetDateTime;

use crate::IntegrationError;

/// Parse an MTA-STS policy text file (RFC 8461).
///
/// Format:
/// ```text
/// version: STSv1
/// mode: enforce
/// mx: mail.example.com
/// mx: *.example.com
/// max_age: 86400
/// ```
pub fn parse_mta_sts_policy(
    raw: &str,
    domain: &str,
    dnssec: DnssecState,
) -> Result<MtaStsPolicy, IntegrationError> {
    let mut version = None;
    let mut mode = None;
    let mut mx_patterns = Vec::new();
    let mut max_age = None;

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((key, val)) = line.split_once(':') {
            let key = key.trim().to_ascii_lowercase();
            let val = val.trim();

            match key.as_str() {
                "version" => {
                    if val != "STSv1" {
                        return Err(IntegrationError::Format(format!(
                            "unsupported MTA-STS version: {val}"
                        )));
                    }
                    version = Some(val.to_string());
                }
                "mode" => {
                    let m = match val.to_ascii_lowercase().as_str() {
                        "enforce" => MtaStsMode::Enforce,
                        "testing" => MtaStsMode::Testing,
                        "none" => MtaStsMode::None,
                        other => {
                            return Err(IntegrationError::Format(format!(
                                "invalid MTA-STS mode: {other}"
                            )));
                        }
                    };
                    mode = Some(m);
                }
                "mx" => {
                    if !val.is_empty() {
                        mx_patterns.push(val.to_string());
                    }
                }
                "max_age" => {
                    let parsed: u32 = val.parse().map_err(|e| {
                        IntegrationError::Format(format!("invalid max_age '{val}': {e}"))
                    })?;
                    max_age = Some(parsed);
                }
                _ => {
                    // Unknown fields are ignored per RFC 8461 Section 3.2
                }
            }
        }
    }

    let version = version
        .ok_or_else(|| IntegrationError::Format("missing 'version' in MTA-STS policy".into()))?;
    let mode =
        mode.ok_or_else(|| IntegrationError::Format("missing 'mode' in MTA-STS policy".into()))?;
    let max_age_seconds = max_age
        .ok_or_else(|| IntegrationError::Format("missing 'max_age' in MTA-STS policy".into()))?;

    Ok(MtaStsPolicy {
        domain: domain.to_string(),
        version,
        mode,
        mx_patterns,
        max_age_seconds,
        dnssec,
        checked_at: OffsetDateTime::now_utc(),
    })
}

/// Matches a hostname against an MTA-STS pattern (e.g. `*.example.com` or `mail.example.com`).
pub fn matches_mx_pattern(hostname: &str, pattern: &str) -> bool {
    let hostname = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();

    if pattern == hostname {
        return true;
    }

    if let Some(suffix) = pattern.strip_prefix("*.")
        && hostname.ends_with(&format!(".{suffix}"))
    {
        return true;
    }

    false
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MtaStsValidationResult {
    Compliant,
    PolicyModeNone,
    MxPatternMismatch {
        hostname: String,
        allowed_patterns: Vec<String>,
    },
    StartTlsNotNegotiated,
    CertificateExpired,
    CertificateInvalid(String),
}

/// Evaluate an observed session against an active MTA-STS policy.
pub fn evaluate_session_against_mta_sts(
    policy: &MtaStsPolicy,
    session: &EmailSession,
    cert_observation: Option<&CertificateObservation>,
    receiving_hostname: Option<&str>,
) -> MtaStsValidationResult {
    evaluate_transport_against_mta_sts(
        policy,
        session.tls_version.is_some(),
        cert_observation,
        receiving_hostname,
        session.last_seen,
    )
}

/// Shared policy comparison for passive sessions and verified active transport.
pub fn evaluate_transport_against_mta_sts(
    policy: &MtaStsPolicy,
    tls_established: bool,
    cert_observation: Option<&CertificateObservation>,
    receiving_hostname: Option<&str>,
    observed_at: OffsetDateTime,
) -> MtaStsValidationResult {
    if policy.mode == MtaStsMode::None {
        return MtaStsValidationResult::PolicyModeNone;
    }

    // 1. Verify hostname against MX patterns if hostname is available
    if let Some(host) = receiving_hostname {
        let matched = policy
            .mx_patterns
            .iter()
            .any(|pat| matches_mx_pattern(host, pat));
        if !matched && !policy.mx_patterns.is_empty() {
            return MtaStsValidationResult::MxPatternMismatch {
                hostname: host.to_string(),
                allowed_patterns: policy.mx_patterns.clone(),
            };
        }
    }

    // 2. In enforce mode, TLS must be negotiated
    if policy.mode == MtaStsMode::Enforce {
        if !tls_established {
            return MtaStsValidationResult::StartTlsNotNegotiated;
        }

        // 3. Leaf certificate must be valid
        if let Some(cert) = cert_observation {
            let now = observed_at;
            if now > cert.validity.not_after {
                return MtaStsValidationResult::CertificateExpired;
            }
            if now < cert.validity.not_before {
                return MtaStsValidationResult::CertificateInvalid(
                    "certificate not yet valid".to_string(),
                );
            }
        }
    }

    MtaStsValidationResult::Compliant
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_mta_sts() {
        let raw = r#"
version: STSv1
mode: enforce
mx: mail.example.com
mx: *.example.com
max_age: 604800
"#;
        let policy = parse_mta_sts_policy(raw, "example.com", DnssecState::Secure).unwrap();
        assert_eq!(policy.version, "STSv1");
        assert_eq!(policy.mode, MtaStsMode::Enforce);
        assert_eq!(
            policy.mx_patterns,
            vec!["mail.example.com", "*.example.com"]
        );
        assert_eq!(policy.max_age_seconds, 604800);
        assert_eq!(policy.dnssec, DnssecState::Secure);
    }

    #[test]
    fn test_mx_pattern_matching() {
        assert!(matches_mx_pattern("mail.example.com", "mail.example.com"));
        assert!(matches_mx_pattern("mx1.example.com", "*.example.com"));
        assert!(!matches_mx_pattern("example.com", "*.example.com"));
        assert!(!matches_mx_pattern("attacker.com", "*.example.com"));
    }
}
