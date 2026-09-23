use mailent_domain::{CtCertificateRecord, CtIntelligenceEvent, CtIntelligenceEventKind};
use time::OffsetDateTime;
use uuid::Uuid;

/// Evaluates a Certificate Transparency record against known certificates observed on the network.
pub fn evaluate_ct_certificate_event(
    ct_cert: &CtCertificateRecord,
    previously_known_ct_certs: &[CtCertificateRecord],
    expected_issuers: &[String],
    observed_on_network_now: bool,
) -> Vec<CtIntelligenceEvent> {
    let mut events = Vec::new();
    let now = OffsetDateTime::now_utc();

    let is_new_ct = !previously_known_ct_certs
        .iter()
        .any(|c| c.sha256_fingerprint == ct_cert.sha256_fingerprint);

    if is_new_ct {
        events.push(CtIntelligenceEvent {
            id: Uuid::new_v4(),
            domain: ct_cert.domain.clone(),
            fingerprint: ct_cert.sha256_fingerprint.clone(),
            kind: CtIntelligenceEventKind::NewCtCertificate,
            title: "New Certificate Discovered in CT Logs".to_string(),
            description: format!(
                "Certificate for {} issued by '{}' logged to public CT",
                ct_cert.domain, ct_cert.issuer
            ),
            observed_at: now,
        });

        // Check if issuer is unexpected
        if !expected_issuers.is_empty()
            && !expected_issuers
                .iter()
                .any(|exp| ct_cert.issuer.contains(exp))
        {
            events.push(CtIntelligenceEvent {
                id: Uuid::new_v4(),
                domain: ct_cert.domain.clone(),
                fingerprint: ct_cert.sha256_fingerprint.clone(),
                kind: CtIntelligenceEventKind::UnexpectedCtIssuer,
                title: "Unexpected Certificate Authority in CT Logs".to_string(),
                description: format!(
                    "Certificate for {} was issued by unexpected CA: '{}'",
                    ct_cert.domain, ct_cert.issuer
                ),
                observed_at: now,
            });
        }
    }

    if observed_on_network_now && !ct_cert.observed_on_network {
        events.push(CtIntelligenceEvent {
            id: Uuid::new_v4(),
            domain: ct_cert.domain.clone(),
            fingerprint: ct_cert.sha256_fingerprint.clone(),
            kind: CtIntelligenceEventKind::CtCertNowObservedOnMailServer,
            title: "CT Certificate Now Active in Mail Traffic".to_string(),
            description: format!(
                "Certificate '{}' previously observed in CT is now active on the mail server",
                ct_cert.sha256_fingerprint
            ),
            observed_at: now,
        });
    }

    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_new_certificate_and_unexpected_issuer() {
        let cert = CtCertificateRecord {
            sha256_fingerprint: "abc123def456".to_string(),
            domain: "corp.example".to_string(),
            names: vec!["mail.corp.example".to_string()],
            issuer: "CN=Unknown Foreign CA".to_string(),
            not_before: OffsetDateTime::now_utc(),
            not_after: OffsetDateTime::now_utc(),
            ct_first_seen: OffsetDateTime::now_utc(),
            observed_on_network: false,
            first_network_observation: None,
        };

        let expected_issuers = vec!["Let's Encrypt".to_string(), "DigiCert".to_string()];
        let events = evaluate_ct_certificate_event(&cert, &[], &expected_issuers, false);

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, CtIntelligenceEventKind::NewCtCertificate);
        assert_eq!(events[1].kind, CtIntelligenceEventKind::UnexpectedCtIssuer);
    }
}
