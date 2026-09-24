use mailent_domain::{EmailSession, Finding, FindingCandidate};
use std::collections::BTreeMap;
use uuid::Uuid;

pub mod drift;
pub mod posture;

pub use drift::*;
pub use posture::{PostureInput, build_guidance, compute_posture};

/// Correlator responsible for converting low-level FindingCandidate records
/// into aggregated, durable Finding domain entities.
pub struct FindingCorrelator;

impl FindingCorrelator {
    /// Correlates a batch of finding candidates from a session into deduplicated Findings.
    pub fn correlate_session(
        session: &EmailSession,
        candidates: &[FindingCandidate],
    ) -> Vec<Finding> {
        let mut grouped: BTreeMap<(&str, &str, &str), Vec<&FindingCandidate>> = BTreeMap::new();

        for candidate in candidates {
            grouped
                .entry((
                    &candidate.policy_name,
                    &candidate.policy_version,
                    &candidate.rule_id,
                ))
                .or_default()
                .push(candidate);
        }

        let mut findings = Vec::with_capacity(grouped.len());

        for ((policy_name, policy_version, rule_id), items) in grouped {
            let first = items[0];
            let mut all_evidence = Vec::new();

            for item in &items {
                all_evidence.extend(item.evidence.iter().cloned());
            }

            findings.push(Finding {
                id: Uuid::new_v5(
                    &Uuid::NAMESPACE_OID,
                    format!(
                        "{}:{policy_name}:{policy_version}:{rule_id}",
                        session.session_id
                    )
                    .as_bytes(),
                ),
                rule_id: rule_id.into(),
                policy_name: policy_name.into(),
                policy_version: policy_version.into(),
                reference: first.reference.clone(),
                severity: first.severity,
                category: first.category,
                title: first.title.clone(),
                description: first.description.clone(),
                remediation: first.remediation.clone(),
                affected_count: 1,
                first_seen: session.first_seen,
                last_seen: session.last_seen,
                evidence: all_evidence,
                organization_id: None,
            });
        }

        findings
    }
}

use mailent_domain::{
    AnomalySignal, DecisionResult, DriftEvent, Investigation, InvestigationStatus, PriorityLevel,
    RiskLevel,
};

/// Correlates multiple security signals (findings, drifts, anomalies, external intelligence,
/// and Jev assistive decisions) into a unified, actionable Investigation.
pub struct InvestigationCorrelator;

impl InvestigationCorrelator {
    pub fn correlate_incident(
        asset_id: Uuid,
        findings: &[Finding],
        drifts: &[DriftEvent],
        anomalies: &[AnomalySignal],
        external_intel: serde_json::Value,
        jev_decision: Option<DecisionResult>,
        observed_at: time::OffsetDateTime,
    ) -> Option<Investigation> {
        if findings.is_empty() && drifts.is_empty() && anomalies.is_empty() {
            return None;
        }

        let title = if let Some(ref jev) = jev_decision {
            if !jev.reasons.is_empty() {
                format!("Review: {}", jev.reasons[0])
            } else if !findings.is_empty() {
                format!("Review: {}", findings[0].title)
            } else {
                format!("Unusual activity: {} signals detected", anomalies.len())
            }
        } else if !findings.is_empty() {
            format!("Review: {}", findings[0].title)
        } else if !anomalies.is_empty() {
            format!("Unusual activity: {}", anomalies[0].title)
        } else {
            format!("Settings changed: {}", drifts[0].title)
        };

        let summary = format!(
            "{} findings, {} settings changes, and {} unusual changes to review.",
            findings.len(),
            drifts.len(),
            anomalies.len()
        );

        let (risk, priority) = if let Some(ref j) = jev_decision {
            (j.risk, j.priority)
        } else {
            let has_critical = findings
                .iter()
                .any(|f| f.severity == mailent_domain::FindingSeverity::Critical);
            let has_high = findings
                .iter()
                .any(|f| f.severity == mailent_domain::FindingSeverity::High)
                || anomalies.iter().any(|a| {
                    a.signal == "NewDaneMismatch" || a.signal == "InternalExternalInconsistency"
                });

            if has_critical {
                (RiskLevel::Critical, PriorityLevel::Immediate)
            } else if has_high {
                (RiskLevel::High, PriorityLevel::High)
            } else if !findings.is_empty() || !anomalies.is_empty() {
                (RiskLevel::Medium, PriorityLevel::Normal)
            } else {
                (RiskLevel::Low, PriorityLevel::Low)
            }
        };

        let finding_ids = findings.iter().map(|f| f.rule_id.clone()).collect();
        let drift_event_ids = drifts.iter().map(|d| d.id).collect();
        let anomaly_ids = anomalies.iter().map(|a| a.id).collect();

        // Stable ID per asset to consolidate multiple signals into one coherent investigation
        let id = Uuid::new_v5(&asset_id, b"investigation:correlated");

        Some(Investigation {
            id,
            asset_id,
            title,
            summary,
            status: InvestigationStatus::Open,
            risk,
            priority,
            finding_ids,
            drift_event_ids,
            anomaly_ids,
            external_intelligence: external_intel,
            jev_decision,
            first_observed: observed_at,
            last_observed: observed_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailent_domain::{
        EmailProtocol, EvidenceRef, FindingCategory, FindingSeverity, NetworkFlow, StartTlsState,
    };
    use time::OffsetDateTime;

    #[test]
    fn test_correlate_session_deduplication() {
        let now = OffsetDateTime::now_utc();
        let session = EmailSession {
            session_id: Uuid::new_v4(),
            sensor_id: "test-sensor".into(),
            provenance: mailent_domain::ObservationProvenance {
                source: "synthetic".into(),
                parser: "mailent-fixture".into(),
                parser_version: "1".into(),
            },
            flow: NetworkFlow {
                src_ip: "10.0.0.1".to_string(),
                src_port: 1000,
                dst_ip: "10.0.0.2".to_string(),
                dst_port: 25,
            },
            protocol: EmailProtocol::Smtp,
            starttls_state: Some(StartTlsState::AdvertisedAndUsed),
            tls_version: None,
            cipher_suite: None,
            key_exchange: None,
            certificate: None,
            capture: None,
            first_seen: now,
            last_seen: now,
        };

        let candidate1 = FindingCandidate {
            rule_id: "TLS_LEGACY_VERSION".to_string(),
            policy_name: "modern".into(),
            policy_version: "1.0.0".into(),
            reference: "rfc8996".into(),
            severity: FindingSeverity::Critical,
            category: FindingCategory::TlsConfiguration,
            title: "Legacy TLS".to_string(),
            description: "TLS 1.0 used".to_string(),
            remediation: "Upgrade".to_string(),
            evidence: vec![EvidenceRef {
                session_id: Some(session.session_id),
                observation_id: None,
                description: "Observed TLS 1.0".to_string(),
            }],
        };

        let candidate2 = FindingCandidate {
            rule_id: "TLS_LEGACY_VERSION".to_string(),
            policy_name: "modern".into(),
            policy_version: "1.0.0".into(),
            reference: "rfc8996".into(),
            severity: FindingSeverity::Critical,
            category: FindingCategory::TlsConfiguration,
            title: "Legacy TLS".to_string(),
            description: "TLS 1.0 used again".to_string(),
            remediation: "Upgrade".to_string(),
            evidence: vec![EvidenceRef {
                session_id: Some(session.session_id),
                observation_id: None,
                description: "Second observation".to_string(),
            }],
        };

        let findings = FindingCorrelator::correlate_session(&session, &[candidate1, candidate2]);
        assert_eq!(
            findings.len(),
            1,
            "Should deduplicate candidates with identical rule_id"
        );
        assert_eq!(findings[0].affected_count, 1);
        assert_eq!(findings[0].evidence.len(), 2);
        assert_eq!(findings[0].rule_id, "TLS_LEGACY_VERSION");
    }

    #[test]
    fn test_correlate_investigation() {
        let asset_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let finding = Finding {
            id: Uuid::new_v4(),
            rule_id: "RULE_STARTTLS_STRIPPED".to_string(),
            policy_name: "RFC 7817".to_string(),
            policy_version: "1.0".to_string(),
            reference: "RFC 7817".to_string(),
            severity: FindingSeverity::Critical,
            category: FindingCategory::ProtocolDowngrade,
            title: "STARTTLS Stripped".to_string(),
            description: "Plaintext downgrade".to_string(),
            remediation: "Block plaintext".to_string(),
            affected_count: 1,
            first_seen: now,
            last_seen: now,
            evidence: vec![],
            organization_id: None,
        };

        let anomaly = AnomalySignal {
            id: Uuid::new_v4(),
            asset_id,
            signal: "StarttlsSuccessRateDrop".to_string(),
            title: "STARTTLS rate drop".to_string(),
            current_value: "failed".to_string(),
            baseline_value: "100%".to_string(),
            deviation: 1.0,
            confidence: 0.9,
            evidence: "Drop from 100% to 0%".to_string(),
            observed_at: now,
        };

        let jev_decision = DecisionResult {
            risk: RiskLevel::Critical,
            anomalous: true,
            human_review: true,
            priority: PriorityLevel::Immediate,
            confidence: 0.95,
            provider_info: "jev:openjev-0.1".to_string(),
            reasons: vec!["Active plaintext downgrade attack".to_string()],
        };

        let inv = InvestigationCorrelator::correlate_incident(
            asset_id,
            &[finding],
            &[],
            &[anomaly],
            serde_json::json!({"mta_sts": "enforce"}),
            Some(jev_decision),
            now,
        );

        assert!(inv.is_some());
        let inv = inv.unwrap();
        assert_eq!(inv.risk, RiskLevel::Critical);
        assert_eq!(inv.priority, PriorityLevel::Immediate);
        assert_eq!(
            inv.title,
            "Review: Active plaintext downgrade attack"
        );
        assert_eq!(inv.finding_ids, vec!["RULE_STARTTLS_STRIPPED"]);
        assert_eq!(inv.status, InvestigationStatus::Open);
    }
}
