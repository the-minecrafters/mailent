use mailent_domain::{EmailSession, FindingSeverity, NormalizedObservation};
use mailent_policy::{PolicyPack, evaluate};

#[test]
fn policy_files_change_predicates_and_severity() {
    let obs: NormalizedObservation = serde_json::from_str(include_str!(
        "../../../fixtures/synthetic/smtp_static_rsa.json"
    ))
    .unwrap();
    let session = EmailSession::from(&obs);
    let modern = PolicyPack::modern();
    let strict =
        PolicyPack::from_yaml(include_str!("../../../policies/high-security/policy.yaml")).unwrap();
    let legacy = PolicyPack::from_yaml(include_str!(
        "../../../policies/legacy-compatible/policy.yaml"
    ))
    .unwrap();
    assert_eq!(evaluate(&session, &modern).len(), 1);
    let strict_findings = evaluate(&session, &strict);
    assert_eq!(strict_findings.len(), 2);
    assert!(
        strict_findings
            .iter()
            .any(|f| f.rule_id == "TLS_MINIMUM_VERSION")
    );
    assert!(
        strict_findings
            .iter()
            .all(|f| f.severity == FindingSeverity::Critical)
    );
    assert!(evaluate(&session, &legacy).is_empty());
    let tls10: NormalizedObservation = serde_json::from_str(include_str!(
        "../../../fixtures/synthetic/smtp_tls10_legacy.json"
    ))
    .unwrap();
    assert_eq!(
        evaluate(&EmailSession::from(&tls10), &legacy)[0].severity,
        FindingSeverity::Medium
    );
}

#[test]
fn rejects_unknown_predicates_typos_duplicates_and_empty_packs() {
    let yaml = include_str!("../../../policies/modern/policy.yaml");
    assert!(PolicyPack::from_yaml(&yaml.replace("certificate_expired", "invented_check")).is_err());
    assert!(PolicyPack::from_yaml(&yaml.replace("severity:", "severty:")).is_err());
    assert!(
        PolicyPack::from_yaml(&yaml.replace("CERTIFICATE_EXPIRED", "TLS_LEGACY_VERSION")).is_err()
    );
    assert!(
        PolicyPack::from_yaml("name: empty\nversion: 1\ndescription: empty\nrules: []").is_err()
    );
}

#[test]
fn expiration_uses_evidence_time_and_inclusive_validity_end() {
    let mut obs: NormalizedObservation = serde_json::from_str(include_str!(
        "../../../fixtures/synthetic/smtp_cert_expired.json"
    ))
    .unwrap();
    obs.timestamp = obs.certificate.as_ref().unwrap().validity.not_after;
    assert!(evaluate(&EmailSession::from(&obs), &PolicyPack::modern()).is_empty());
    obs.timestamp += time::Duration::seconds(1);
    assert_eq!(
        evaluate(&EmailSession::from(&obs), &PolicyPack::modern()).len(),
        1
    );
}

#[test]
fn starttls_finding_requires_explicit_smtp_absence_not_missing_capture_data() {
    use mailent_domain::{EmailProtocol, StartTlsState};
    let obs: NormalizedObservation = serde_json::from_str(include_str!(
        "../../../fixtures/synthetic/smtp_tls13_healthy.json"
    ))
    .unwrap();
    let mut session = EmailSession::from(&obs);
    for state in [
        None,
        Some(StartTlsState::AdvertisedNotUsed),
        Some(StartTlsState::AdvertisedAndUsed),
    ] {
        session.starttls_state = state;
        assert!(evaluate(&session, &PolicyPack::modern()).is_empty());
    }
    session.starttls_state = Some(StartTlsState::NotAdvertised);
    assert_eq!(
        evaluate(&session, &PolicyPack::modern())[0].rule_id,
        "STARTTLS_MISSING"
    );
    for failure_state in [
        StartTlsState::Rejected,
        StartTlsState::FailedHandshake,
        StartTlsState::PlaintextContinuation,
    ] {
        session.starttls_state = Some(failure_state);
        let findings = evaluate(&session, &PolicyPack::modern());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "STARTTLS_MISSING");
    }
    session.protocol = EmailProtocol::Imap;
    assert!(evaluate(&session, &PolicyPack::modern()).is_empty());
}
