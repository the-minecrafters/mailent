use crate::{PolicyPack, Predicate};
use mailent_domain::{EmailSession, EvidenceRef, FindingCandidate, FindingCategory};

pub fn evaluate(session: &EmailSession, policy: &PolicyPack) -> Vec<FindingCandidate> {
    policy
        .rules
        .iter()
        .filter_map(|rule| {
            let (category, description) = match &rule.when {
                Predicate::TlsVersionIn { versions } => {
                    let version = session.tls_version.as_ref()?;
                    if !versions.contains(version) {
                        return None;
                    }
                    (
                        FindingCategory::TlsConfiguration,
                        format!("Observed {} on connection {}", version, session.flow),
                    )
                }
                Predicate::CertificateExpired => {
                    let cert = session.certificate.as_ref()?;
                    if !cert.validity.is_expired_at(session.last_seen) {
                        return None;
                    }
                    (
                        FindingCategory::Certificate,
                        format!(
                            "Certificate '{}' (SHA256: {}) expired at {}; observation time: {}",
                            cert.reference.subject,
                            cert.reference.sha256_fingerprint,
                            cert.validity.not_after,
                            session.last_seen
                        ),
                    )
                }
                Predicate::KeyExchangeIn { values } => {
                    let key_exchange = session.key_exchange.as_ref()?;
                    if !values.contains(key_exchange) {
                        return None;
                    }
                    (
                        FindingCategory::TlsConfiguration,
                        format!(
                            "Observed key exchange: {:?} on {}",
                            key_exchange, session.flow
                        ),
                    )
                }
            };
            Some(FindingCandidate {
                rule_id: rule.id.clone(),
                policy_name: policy.name.clone(),
                policy_version: policy.version.clone(),
                reference: rule.reference.clone(),
                severity: rule.severity,
                category,
                title: rule.title.clone(),
                description: description.clone(),
                remediation: rule.remediation.clone(),
                evidence: vec![EvidenceRef {
                    session_id: Some(session.session_id),
                    observation_id: Some(session.session_id),
                    description,
                }],
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailent_domain::{
        CertificateObservation, CertificateReference, EmailProtocol, FindingSeverity, KeyExchange,
        NetworkFlow, StartTlsState, TlsVersion, ValidityPeriod,
    };
    use time::{Duration, OffsetDateTime};
    use uuid::Uuid;

    fn sample_session(
        version: Option<TlsVersion>,
        kx: Option<KeyExchange>,
        cert: Option<CertificateObservation>,
    ) -> EmailSession {
        let now = OffsetDateTime::now_utc();
        EmailSession {
            session_id: Uuid::new_v4(),
            sensor_id: "test-sensor".into(),
            provenance: mailent_domain::ObservationProvenance {
                source: "synthetic".into(),
                parser: "mailent-fixture".into(),
                parser_version: "1".into(),
            },
            flow: NetworkFlow {
                src_ip: "192.0.2.1".to_string(),
                src_port: 45678,
                dst_ip: "198.51.100.25".to_string(),
                dst_port: 25,
            },
            protocol: EmailProtocol::Smtp,
            starttls_state: Some(StartTlsState::AdvertisedAndUsed),
            tls_version: version,
            cipher_suite: None,
            key_exchange: kx,
            certificate: cert,
            capture: None,
            first_seen: now,
            last_seen: now,
        }
    }

    #[test]
    fn test_tls13_healthy_has_no_legacy_findings() {
        let policy = PolicyPack::modern();
        let session = sample_session(Some(TlsVersion::Tls13), Some(KeyExchange::Ecdhe), None);
        let findings = evaluate(&session, &policy);
        assert!(findings.is_empty(), "TLS 1.3 should produce 0 findings");
    }

    #[test]
    fn test_tls10_triggers_legacy_finding() {
        let policy = PolicyPack::modern();
        let session = sample_session(Some(TlsVersion::Tls10), Some(KeyExchange::Ecdhe), None);
        let findings = evaluate(&session, &policy);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "TLS_LEGACY_VERSION");
        assert_eq!(findings[0].severity, FindingSeverity::Critical);
    }

    #[test]
    fn test_expired_certificate_triggers_finding() {
        let policy = PolicyPack::modern();
        let now = OffsetDateTime::now_utc();
        let expired_cert = CertificateObservation {
            reference: CertificateReference {
                sha256_fingerprint:
                    "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b".to_string(),
                subject: "CN=mail.legacy-corp.example".to_string(),
                issuer: "CN=Example Root CA".to_string(),
            },
            validity: ValidityPeriod {
                not_before: now - Duration::days(400),
                not_after: now - Duration::days(10), // expired 10 days ago
            },
            is_self_signed: Some(false),
            san: vec!["mail.legacy-corp.example".to_string()],
        };

        let session = sample_session(
            Some(TlsVersion::Tls12),
            Some(KeyExchange::Ecdhe),
            Some(expired_cert),
        );
        let findings = evaluate(&session, &policy);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "CERTIFICATE_EXPIRED");
        assert_eq!(findings[0].severity, FindingSeverity::High);
    }

    #[test]
    fn test_static_rsa_triggers_no_forward_secrecy() {
        let policy = PolicyPack::modern();
        let session = sample_session(Some(TlsVersion::Tls12), Some(KeyExchange::RsaStatic), None);
        let findings = evaluate(&session, &policy);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "NO_FORWARD_SECRECY");
        assert_eq!(findings[0].severity, FindingSeverity::High);
    }

    #[test]
    fn test_combined_legacy_tls_and_static_rsa() {
        let policy = PolicyPack::modern();
        let session = sample_session(Some(TlsVersion::Tls10), Some(KeyExchange::RsaStatic), None);
        let findings = evaluate(&session, &policy);
        assert_eq!(findings.len(), 2);
        let rule_ids: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rule_ids.contains(&"TLS_LEGACY_VERSION"));
        assert!(rule_ids.contains(&"NO_FORWARD_SECRECY"));
    }
}
