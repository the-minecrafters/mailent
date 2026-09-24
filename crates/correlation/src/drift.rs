use mailent_domain::{
    AssessmentRecord, AssessmentSource, DriftEvent, DriftKind, Finding, FindingSeverity,
    Investigation, InvestigationStatus, PriorityLevel, RiskLevel,
};
use std::collections::{HashMap, HashSet};
use time::OffsetDateTime;
use uuid::Uuid;

/// Correlator responsible for comparing two successive infrastructure assessments
/// of the same domain to identify configuration changes, security regressions,
/// and resolved findings.
pub struct InfrastructureDriftCorrelator;

impl InfrastructureDriftCorrelator {
    /// Compares a previous assessment against the current assessment of the same target domain.
    ///
    /// Respects the core invariant: **Change ≠ Finding**.
    /// A configuration change (such as an MX rotation, new endpoint, or certificate renewal)
    /// is recorded as a typed `DriftEvent`. Only changes that represent security degradation
    /// (such as STARTTLS lost, legacy TLS enabled, forward secrecy removed, or certificate expiry)
    /// are flagged as security regressions.
    pub fn compare_assessments(
        previous: &AssessmentRecord,
        current: &AssessmentRecord,
        prev_findings: &[Finding],
        curr_findings: &[Finding],
    ) -> Vec<DriftEvent> {
        let mut drifts = Vec::new();
        let now = OffsetDateTime::now_utc();
        let asset_id = current.asset_ids.first().copied().unwrap_or(current.id);
        let domain = match (&previous.source, &current.source) {
            (AssessmentSource::Infrastructure(p), AssessmentSource::Infrastructure(c)) => {
                if p.target_domain == c.target_domain {
                    Some(c.target_domain.clone())
                } else {
                    None
                }
            }
            _ => None,
        };

        // 1. Compare Discovered Endpoints and Services
        if let (
            AssessmentSource::Infrastructure(prev_meta),
            AssessmentSource::Infrastructure(curr_meta),
        ) = (&previous.source, &current.source)
        {
            let prev_endpoints: HashMap<String, &mailent_domain::DiscoveredEndpoint> = prev_meta
                .discovered_endpoints
                .iter()
                .map(|e| (format!("{}:{}", e.host, e.port), e))
                .collect();

            let curr_endpoints: HashMap<String, &mailent_domain::DiscoveredEndpoint> = curr_meta
                .discovered_endpoints
                .iter()
                .map(|e| (format!("{}:{}", e.host, e.port), e))
                .collect();

            // Endpoints added
            for (key, curr_ep) in &curr_endpoints {
                if !prev_endpoints.contains_key(key) {
                    drifts.push(DriftEvent {
                        id: Uuid::new_v4(),
                        asset_id,
                        kind: DriftKind::EndpointAdded,
                        title: "Service Endpoint Added".to_string(),
                        description: format!(
                            "Discovered new {} endpoint on {}:{}",
                            curr_ep.service, curr_ep.host, curr_ep.port
                        ),
                        previous_value: None,
                        new_value: format!("{}:{}", curr_ep.host, curr_ep.port),
                        observed_at: now,
                        session_id: None,
                        assessment_id: Some(current.id),
                        domain: domain.clone(),
                        organization_id: current.organization_id,
                    });
                }
            }

            // Endpoints removed
            for (key, prev_ep) in &prev_endpoints {
                if !curr_endpoints.contains_key(key) {
                    drifts.push(DriftEvent {
                        id: Uuid::new_v4(),
                        asset_id,
                        kind: DriftKind::EndpointRemoved,
                        title: "Service Endpoint Removed".to_string(),
                        description: format!(
                            "Previously detected {} endpoint {}:{} is no longer present",
                            prev_ep.service, prev_ep.host, prev_ep.port
                        ),
                        previous_value: Some(format!("{}:{}", prev_ep.host, prev_ep.port)),
                        new_value: "Removed".to_string(),
                        observed_at: now,
                        session_id: None,
                        assessment_id: Some(current.id),
                        domain: domain.clone(),
                        organization_id: current.organization_id,
                    });
                }
            }

            // MX Hosts comparison
            let prev_mx: HashSet<&str> = prev_meta
                .discovered_endpoints
                .iter()
                .filter(|e| e.service.eq_ignore_ascii_case("smtp"))
                .map(|e| e.host.as_str())
                .collect();
            let curr_mx: HashSet<&str> = curr_meta
                .discovered_endpoints
                .iter()
                .filter(|e| e.service.eq_ignore_ascii_case("smtp"))
                .map(|e| e.host.as_str())
                .collect();

            for host in curr_mx.difference(&prev_mx) {
                drifts.push(DriftEvent {
                    id: Uuid::new_v4(),
                    asset_id,
                    kind: DriftKind::MxAdded,
                    title: "MX Host Added".to_string(),
                    description: format!("New MX host {host} published for domain"),
                    previous_value: None,
                    new_value: (*host).to_string(),
                    observed_at: now,
                    session_id: None,
                    assessment_id: Some(current.id),
                    domain: domain.clone(),
                    organization_id: current.organization_id,
                });
            }

            for host in prev_mx.difference(&curr_mx) {
                drifts.push(DriftEvent {
                    id: Uuid::new_v4(),
                    asset_id,
                    kind: DriftKind::MxRemoved,
                    title: "MX Host Removed".to_string(),
                    description: format!("Previous MX host {host} removed from domain DNS"),
                    previous_value: Some((*host).to_string()),
                    new_value: "Removed".to_string(),
                    observed_at: now,
                    session_id: None,
                    assessment_id: Some(current.id),
                    domain: domain.clone(),
                    organization_id: current.organization_id,
                });
            }
        }

        // 2. Compare Finding Differences (Introduced vs Resolved)
        let prev_rule_map: HashMap<&str, &Finding> = prev_findings
            .iter()
            .map(|f| (f.rule_id.as_str(), f))
            .collect();
        let curr_rule_map: HashMap<&str, &Finding> = curr_findings
            .iter()
            .map(|f| (f.rule_id.as_str(), f))
            .collect();

        // Findings introduced
        for (rule_id, finding) in &curr_rule_map {
            if !prev_rule_map.contains_key(rule_id) {
                // Determine specific typed drift event based on rule_id
                let (kind, title) = match *rule_id {
                    "STARTTLS_DISABLED" | "STARTTLS-001" | "STARTTLS_MISSING" => (
                        DriftKind::StartTlsLost,
                        format!("STARTTLS Lost: {}", finding.title),
                    ),
                    "TLS_LEGACY_VERSION" | "TLS-001" => (
                        DriftKind::LegacyTlsEnabled,
                        format!("Legacy TLS Enabled: {}", finding.title),
                    ),
                    "TLS_NO_PFS" | "TLS-002" | "NO_FORWARD_SECRECY" => (
                        DriftKind::ForwardSecrecyLost,
                        format!("Forward Secrecy Lost: {}", finding.title),
                    ),
                    "CERT_EXPIRED" | "CERT-001" | "CERTIFICATE_EXPIRED" => (
                        DriftKind::CertificateExpired,
                        format!("Certificate Expired: {}", finding.title),
                    ),
                    "CERT_UNTRUSTED" | "CERT-002" => (
                        DriftKind::CertificateTrustChanged,
                        format!("Certificate Trust Regressed: {}", finding.title),
                    ),
                    "MTA_STS_DISABLED" | "MTASTS-001" | "MTA_STS_POLICY_MISSING" => (
                        DriftKind::MtaStsChanged,
                        format!("MTA-STS Security Weakened: {}", finding.title),
                    ),
                    "DANE_TLSA_RECORD_MISMATCH"
                    | "DANE_TLSA_RECORD_MISSING"
                    | "DANE_DNSSEC_INSECURE" => (
                        DriftKind::DaneChanged,
                        format!("DANE Security Weakened: {}", finding.title),
                    ),
                    _ => (
                        DriftKind::FindingIntroduced,
                        format!("New Finding: {}", finding.title),
                    ),
                };

                drifts.push(DriftEvent {
                    id: Uuid::new_v4(),
                    asset_id,
                    kind,
                    title,
                    description: finding.description.clone(),
                    previous_value: None,
                    new_value: format!("{}: {}", finding.severity, finding.title),
                    observed_at: now,
                    session_id: None,
                    assessment_id: Some(current.id),
                    domain: domain.clone(),
                    organization_id: current.organization_id,
                });
            }
        }

        // Findings resolved
        for (rule_id, finding) in &prev_rule_map {
            if !curr_rule_map.contains_key(rule_id) {
                let (kind, title) = match *rule_id {
                    "STARTTLS_DISABLED" | "STARTTLS-001" | "STARTTLS_MISSING" => (
                        DriftKind::StartTlsRestored,
                        format!("STARTTLS Restored: {}", finding.title),
                    ),
                    "TLS_LEGACY_VERSION" | "TLS-001" => (
                        DriftKind::LegacyTlsDisabled,
                        format!("Legacy TLS Disabled: {}", finding.title),
                    ),
                    "TLS_NO_PFS" | "TLS-002" | "NO_FORWARD_SECRECY" => (
                        DriftKind::ForwardSecrecyRestored,
                        format!("Forward Secrecy Restored: {}", finding.title),
                    ),
                    "CERT_EXPIRED" | "CERT-001" | "CERTIFICATE_EXPIRED" => (
                        DriftKind::CertificateRenewed,
                        format!("Certificate Renewed: {}", finding.title),
                    ),
                    _ => (
                        DriftKind::FindingResolved,
                        format!("Finding Resolved: {}", finding.title),
                    ),
                };

                drifts.push(DriftEvent {
                    id: Uuid::new_v4(),
                    asset_id,
                    kind,
                    title,
                    description: format!("Condition '{}' is no longer present", finding.title),
                    previous_value: Some(finding.title.clone()),
                    new_value: "Resolved".to_string(),
                    observed_at: now,
                    session_id: None,
                    assessment_id: Some(current.id),
                    domain: domain.clone(),
                    organization_id: current.organization_id,
                });
            }
        }

        // 3. Posture Score Drift
        let score_diff = current.posture_score - previous.posture_score;
        if score_diff.abs() >= 1.0 {
            drifts.push(DriftEvent {
                id: Uuid::new_v4(),
                asset_id,
                kind: DriftKind::PostureChanged,
                title: format!("Security score changed ({:+.1})", score_diff),
                description: format!(
                    "Security score changed from {:.1} ({}) to {:.1} ({})",
                    previous.posture_score,
                    previous.posture_grade,
                    current.posture_score,
                    current.posture_grade
                ),
                previous_value: Some(format!("{:.1}", previous.posture_score)),
                new_value: format!("{:.1}", current.posture_score),
                observed_at: now,
                session_id: None,
                assessment_id: Some(current.id),
                domain: domain.clone(),
                organization_id: current.organization_id,
            });
        }

        drifts
    }

    /// Evaluates drift events and current findings to determine whether a meaningful
    /// security regression occurred that warrants opening or enriching an investigation.
    pub fn extract_security_regressions<'a>(
        drifts: &'a [DriftEvent],
        current_findings: &[Finding],
    ) -> Vec<&'a DriftEvent> {
        drifts
            .iter()
            .filter(|d| {
                if d.kind.is_security_regression() {
                    return true;
                }
                // Material MTA-STS / DANE regressions
                if matches!(d.kind, DriftKind::MtaStsChanged | DriftKind::DaneChanged) {
                    return true;
                }
                // Major posture regression: score dropped by >= 15 points or dropped to critical (< 40)
                if d.kind == DriftKind::PostureChanged
                    && let (Ok(prev), Ok(curr)) = (
                        d.previous_value.as_deref().unwrap_or("0").parse::<f32>(),
                        d.new_value.parse::<f32>(),
                    )
                    && (curr <= prev - 15.0 || curr < 40.0)
                {
                    return true;
                }
                // Check if new Critical/High finding was introduced
                if d.kind == DriftKind::FindingIntroduced {
                    return current_findings.iter().any(|f| {
                        (f.severity == FindingSeverity::Critical
                            || f.severity == FindingSeverity::High)
                            && (d.new_value.contains(&f.title)
                                || d.description.contains(&f.title)
                                || d.new_value.contains(&f.rule_id))
                    }) || d.new_value.to_lowercase().contains("critical")
                        || d.new_value.to_lowercase().contains("high");
                }
                false
            })
            .collect()
    }

    /// Correlates security regressions into an existing or new Investigation.
    /// Preserves investigation continuity across repeated scheduled scans.
    /// Returns None if no meaningful security regressions exist, keeping benign
    /// drift (routine cert rotation, MX addition) as history/drift only.
    pub fn correlate_or_enrich_investigation(
        existing_investigation: Option<&Investigation>,
        asset_id: Uuid,
        domain: &str,
        regressions: &[&DriftEvent],
        findings: &[Finding],
        observed_at: OffsetDateTime,
    ) -> Option<Investigation> {
        // If there are no meaningful regressions, do not create or enrich an investigation.
        // Benign drift (ordinary cert rotation, MX addition, etc.) remains drift/history only.
        if regressions.is_empty() {
            return None;
        }

        if let Some(existing) = existing_investigation
            && existing.status != InvestigationStatus::Resolved
        {
            // Enrich existing unresolved investigation
            let mut enriched = existing.clone();
            enriched.last_observed = observed_at;

            for r in regressions {
                if !enriched.drift_event_ids.contains(&r.id) {
                    enriched.drift_event_ids.push(r.id);
                }
            }

            for f in findings {
                if (f.severity == FindingSeverity::High || f.severity == FindingSeverity::Critical)
                    && !enriched.finding_ids.contains(&f.rule_id)
                {
                    enriched.finding_ids.push(f.rule_id.clone());
                }
            }

            // Elevate risk/priority if critical regressions appeared
            if regressions.iter().any(|r| {
                matches!(
                    r.kind,
                    DriftKind::StartTlsLost
                        | DriftKind::CertificateExpired
                        | DriftKind::CertificateTrustChanged
                )
            }) || findings
                .iter()
                .any(|f| f.severity == FindingSeverity::Critical)
            {
                enriched.risk = RiskLevel::Critical;
                enriched.priority = PriorityLevel::Immediate;
            }

            return Some(enriched);
        }

        // Open new investigation for meaningful regressions
        let has_critical = regressions.iter().any(|r| {
            matches!(
                r.kind,
                DriftKind::StartTlsLost
                    | DriftKind::CertificateExpired
                    | DriftKind::CertificateTrustChanged
            )
        }) || findings
            .iter()
            .any(|f| f.severity == FindingSeverity::Critical);

        let (risk, priority) = if has_critical {
            (RiskLevel::Critical, PriorityLevel::Immediate)
        } else {
            (RiskLevel::High, PriorityLevel::High)
        };

        let summary = if let Some(first_reg) = regressions.first() {
            format!("{}: {}", first_reg.title, first_reg.description)
        } else if let Some(first_f) = findings.first() {
            format!("{}: {}", first_f.title, first_f.description)
        } else {
            format!("New issues found while checking {domain}")
        };

        let title = if let Some(first_reg) = regressions.first() {
            format!("New issue: {}", first_reg.title)
        } else {
            format!("Review: {domain}")
        };

        let relevant_finding_ids: Vec<String> = findings
            .iter()
            .filter(|f| {
                f.severity == FindingSeverity::High || f.severity == FindingSeverity::Critical
            })
            .map(|f| f.rule_id.clone())
            .collect();

        Some(Investigation {
            id: Uuid::new_v4(),
            asset_id,
            title,
            summary,
            status: InvestigationStatus::Open,
            risk,
            priority,
            finding_ids: if relevant_finding_ids.is_empty() {
                findings.iter().map(|f| f.rule_id.clone()).collect()
            } else {
                relevant_finding_ids
            },
            drift_event_ids: regressions.iter().map(|r| r.id).collect(),
            anomaly_ids: Vec::new(),
            external_intelligence: serde_json::json!({
                "target_domain": domain,
                "regressions_count": regressions.len(),
                "regressions": regressions.iter().map(|r| &r.title).collect::<Vec<_>>(),
            }),
            jev_decision: None,
            first_observed: observed_at,
            last_observed: observed_at,
        })
    }
}

#[cfg(test)]
#[allow(clippy::all)]
mod tests {
    use super::*;
    use mailent_domain::{
        AssessmentRecord, AssessmentSource, DiscoveredEndpoint, Finding, FindingCategory,
        FindingSeverity, InfrastructureMetadata,
    };
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn mock_infra_assessment(
        domain: &str,
        score: f32,
        endpoints: Vec<DiscoveredEndpoint>,
    ) -> AssessmentRecord {
        let now = OffsetDateTime::now_utc();
        AssessmentRecord {
            id: Uuid::new_v4(),
            title: format!("Assessment for {domain}"),
            source: AssessmentSource::Infrastructure(InfrastructureMetadata {
                target_domain: domain.to_string(),
                discovered_endpoints: endpoints,
                scan_start: now,
                scan_end: now,
                discovery_evidence: vec![],
            }),
            capture_name: String::new(),
            capture_hash: String::new(),
            capture_size_bytes: 0,
            created_at: now,
            time_range_start: None,
            time_range_end: None,
            protocols_identified: vec!["smtp".into()],
            protocol_evidence: vec![],
            session_ids: vec![],
            asset_ids: vec![Uuid::new_v4()],
            finding_ids: vec![],
            posture_score: score,
            posture_grade: if score > 80.0 { "A".into() } else { "F".into() },
            evidence_gaps: vec![],
            ai_risk_classification: "low".into(),
            ai_risk_rationale: "ok".into(),
            ai_confidence: 1.0,
            metadata: serde_json::json!({}),
            organization_id: Some(Uuid::new_v4()),
        }
    }

    fn mock_finding(rule_id: &str, title: &str, severity: FindingSeverity) -> Finding {
        let now = OffsetDateTime::now_utc();
        Finding {
            id: Uuid::new_v4(),
            rule_id: rule_id.to_string(),
            policy_name: "Modern Transport".to_string(),
            policy_version: "1.0".to_string(),
            reference: "RFC 8996".to_string(),
            category: FindingCategory::TlsConfiguration,
            severity,
            title: title.to_string(),
            description: format!("Description for {title}"),
            remediation: "Upgrade configuration".to_string(),
            evidence: vec![],
            first_seen: now,
            last_seen: now,
            affected_count: 1,
            organization_id: None,
        }
    }

    #[test]
    fn test_drift_mx_added_and_removed() {
        let ep1 = DiscoveredEndpoint {
            service: "smtp".into(),
            host: "mx1.example.com".into(),
            port: 25,
            priority: Some(10),
            resolved_ips: vec!["192.0.2.1".into()],
        };
        let ep2 = DiscoveredEndpoint {
            service: "smtp".into(),
            host: "mx2.example.com".into(),
            port: 25,
            priority: Some(20),
            resolved_ips: vec!["192.0.2.2".into()],
        };

        let prev = mock_infra_assessment("example.com", 95.0, vec![ep1.clone()]);
        let curr = mock_infra_assessment("example.com", 95.0, vec![ep2.clone()]);

        let drifts = InfrastructureDriftCorrelator::compare_assessments(&prev, &curr, &[], &[]);
        let mx_added = drifts.iter().find(|d| d.kind == DriftKind::MxAdded);
        let mx_removed = drifts.iter().find(|d| d.kind == DriftKind::MxRemoved);

        assert!(mx_added.is_some(), "Expected MxAdded event");
        assert_eq!(mx_added.unwrap().new_value, "mx2.example.com");
        assert!(mx_removed.is_some(), "Expected MxRemoved event");
        assert_eq!(
            mx_removed.unwrap().previous_value.as_deref(),
            Some("mx1.example.com")
        );

        // MX changes are NOT security regressions
        let regressions = InfrastructureDriftCorrelator::extract_security_regressions(&drifts, &[]);
        assert!(
            regressions.is_empty(),
            "MX change must not be marked as a security regression"
        );
    }

    #[test]
    fn test_drift_security_regression_starttls_and_legacy_tls() {
        let ep = DiscoveredEndpoint {
            service: "smtp".into(),
            host: "mx1.example.com".into(),
            port: 25,
            priority: Some(10),
            resolved_ips: vec!["192.0.2.1".into()],
        };

        let prev = mock_infra_assessment("example.com", 95.0, vec![ep.clone()]);
        let curr = mock_infra_assessment("example.com", 45.0, vec![ep.clone()]);

        let f_legacy = mock_finding(
            "TLS_LEGACY_VERSION",
            "TLS 1.0 Accepted",
            FindingSeverity::High,
        );
        let f_starttls = mock_finding(
            "STARTTLS_DISABLED",
            "STARTTLS Missing",
            FindingSeverity::Critical,
        );

        let drifts = InfrastructureDriftCorrelator::compare_assessments(
            &prev,
            &curr,
            &[],
            &[f_legacy.clone(), f_starttls.clone()],
        );

        let regressions = InfrastructureDriftCorrelator::extract_security_regressions(
            &drifts,
            &[f_legacy.clone(), f_starttls.clone()],
        );

        assert_eq!(
            regressions.len(),
            3,
            "Expected 2 finding regressions + 1 posture score drop"
        );
        assert!(
            regressions
                .iter()
                .any(|r| r.kind == DriftKind::StartTlsLost)
        );
        assert!(
            regressions
                .iter()
                .any(|r| r.kind == DriftKind::LegacyTlsEnabled)
        );
        assert!(
            regressions
                .iter()
                .any(|r| r.kind == DriftKind::PostureChanged)
        );
    }

    #[test]
    fn test_drift_findings_resolved_and_corroboration() {
        let ep = DiscoveredEndpoint {
            service: "smtp".into(),
            host: "mx1.example.com".into(),
            port: 25,
            priority: Some(10),
            resolved_ips: vec!["192.0.2.1".into()],
        };

        let prev = mock_infra_assessment("example.com", 60.0, vec![ep.clone()]);
        let curr = mock_infra_assessment("example.com", 95.0, vec![ep.clone()]);

        let f_legacy = mock_finding(
            "TLS_LEGACY_VERSION",
            "TLS 1.0 Accepted",
            FindingSeverity::High,
        );

        // Previous had the finding, current has 0 findings
        let drifts =
            InfrastructureDriftCorrelator::compare_assessments(&prev, &curr, &[f_legacy], &[]);

        let resolved = drifts
            .iter()
            .find(|d| d.kind == DriftKind::LegacyTlsDisabled);
        assert!(
            resolved.is_some(),
            "Expected LegacyTlsDisabled resolution event"
        );

        let regressions = InfrastructureDriftCorrelator::extract_security_regressions(&drifts, &[]);
        assert!(
            regressions.is_empty(),
            "Security improvement must not be marked as a regression"
        );
    }

    #[test]
    fn test_drift_investigation_enrichment_continuity() {
        let ep = DiscoveredEndpoint {
            service: "smtp".into(),
            host: "mx1.example.com".into(),
            port: 25,
            priority: Some(10),
            resolved_ips: vec!["192.0.2.1".into()],
        };

        let prev = mock_infra_assessment("example.com", 90.0, vec![ep.clone()]);
        let curr = mock_infra_assessment("example.com", 60.0, vec![ep.clone()]);

        let f_cert = mock_finding(
            "CERT_EXPIRED",
            "Certificate Expired",
            FindingSeverity::Critical,
        );
        let drifts = InfrastructureDriftCorrelator::compare_assessments(
            &prev,
            &curr,
            &[],
            &[f_cert.clone()],
        );

        let regressions =
            InfrastructureDriftCorrelator::extract_security_regressions(&drifts, &[f_cert.clone()]);

        let now = OffsetDateTime::now_utc();
        let inv1 = InfrastructureDriftCorrelator::correlate_or_enrich_investigation(
            None,
            curr.asset_ids[0],
            "example.com",
            &regressions,
            &[f_cert.clone()],
            now,
        );
        assert!(inv1.is_some());
        let inv1 = inv1.unwrap();
        assert_eq!(inv1.status, InvestigationStatus::Open);
        assert_eq!(inv1.risk, RiskLevel::Critical);

        // Second scheduled assessment arrives: same domain still has the regression
        let later = now + time::Duration::hours(24);
        let inv2 = InfrastructureDriftCorrelator::correlate_or_enrich_investigation(
            Some(&inv1),
            curr.asset_ids[0],
            "example.com",
            &regressions,
            &[f_cert.clone()],
            later,
        );
        assert!(inv2.is_some());
        let inv2 = inv2.unwrap();
        assert_eq!(
            inv2.id, inv1.id,
            "Existing investigation ID must be preserved for continuity"
        );
        assert_eq!(inv2.last_observed, later);
    }

    #[test]
    fn test_investigation_creation_on_all_meaningful_regressions() {
        let ep = DiscoveredEndpoint {
            service: "smtp".into(),
            host: "mx1.example.com".into(),
            port: 25,
            priority: Some(10),
            resolved_ips: vec!["192.0.2.1".into()],
        };

        let prev = mock_infra_assessment("example.com", 95.0, vec![ep.clone()]);
        let curr = mock_infra_assessment("example.com", 30.0, vec![ep.clone()]);

        // 1. STARTTLS lost
        let f_starttls = mock_finding(
            "STARTTLS_MISSING",
            "STARTTLS Missing",
            FindingSeverity::High,
        );
        // 2. Legacy TLS newly enabled
        let f_legacy = mock_finding(
            "TLS_LEGACY_VERSION",
            "TLS 1.0 Accepted",
            FindingSeverity::Critical,
        );
        // 3. Forward Secrecy lost
        let f_pfs = mock_finding(
            "NO_FORWARD_SECRECY",
            "Static RSA without PFS",
            FindingSeverity::High,
        );
        // 4. Certificate expired
        let f_cert = mock_finding(
            "CERTIFICATE_EXPIRED",
            "Certificate Expired",
            FindingSeverity::High,
        );
        // 5. Certificate untrusted
        let f_trust = mock_finding(
            "CERT_UNTRUSTED",
            "Self-signed Untrusted Leaf",
            FindingSeverity::High,
        );
        // 6. Material MTA-STS regression
        let f_mta_sts = mock_finding(
            "MTA_STS_POLICY_MISSING",
            "MTA-STS Policy Missing",
            FindingSeverity::Medium,
        );
        // 7. Material DANE regression
        let f_dane = mock_finding(
            "DANE_TLSA_RECORD_MISMATCH",
            "DANE TLSA Hash Mismatch",
            FindingSeverity::High,
        );

        let all_findings = vec![
            f_starttls, f_legacy, f_pfs, f_cert, f_trust, f_mta_sts, f_dane,
        ];

        let drifts =
            InfrastructureDriftCorrelator::compare_assessments(&prev, &curr, &[], &all_findings);

        let regressions =
            InfrastructureDriftCorrelator::extract_security_regressions(&drifts, &all_findings);

        // Verify each required regression kind was identified
        assert!(
            regressions
                .iter()
                .any(|r| r.kind == DriftKind::StartTlsLost)
        );
        assert!(
            regressions
                .iter()
                .any(|r| r.kind == DriftKind::LegacyTlsEnabled)
        );
        assert!(
            regressions
                .iter()
                .any(|r| r.kind == DriftKind::ForwardSecrecyLost)
        );
        assert!(
            regressions
                .iter()
                .any(|r| r.kind == DriftKind::CertificateExpired)
        );
        assert!(
            regressions
                .iter()
                .any(|r| r.kind == DriftKind::CertificateTrustChanged)
        );
        assert!(
            regressions
                .iter()
                .any(|r| r.kind == DriftKind::MtaStsChanged)
        );
        assert!(regressions.iter().any(|r| r.kind == DriftKind::DaneChanged));
        assert!(
            regressions
                .iter()
                .any(|r| r.kind == DriftKind::PostureChanged)
        );

        // Correlate into investigation
        let now = OffsetDateTime::now_utc();
        let inv = InfrastructureDriftCorrelator::correlate_or_enrich_investigation(
            None,
            curr.asset_ids[0],
            "example.com",
            &regressions,
            &all_findings,
            now,
        );

        assert!(
            inv.is_some(),
            "Meaningful regressions must create an investigation"
        );
        let inv = inv.unwrap();
        assert_eq!(inv.status, InvestigationStatus::Open);
        assert_eq!(inv.risk, RiskLevel::Critical);
        assert_eq!(inv.priority, PriorityLevel::Immediate);
        assert_eq!(inv.asset_id, curr.asset_ids[0]);
        assert_eq!(inv.drift_event_ids.len(), regressions.len());
    }

    #[test]
    fn test_investigation_enrichment_elevates_risk_and_adds_signals() {
        let ep = DiscoveredEndpoint {
            service: "smtp".into(),
            host: "mx1.example.com".into(),
            port: 25,
            priority: Some(10),
            resolved_ips: vec!["192.0.2.1".into()],
        };

        let prev = mock_infra_assessment("example.com", 90.0, vec![ep.clone()]);
        let curr1 = mock_infra_assessment("example.com", 75.0, vec![ep.clone()]);

        // First regression: Forward Secrecy lost (High risk)
        let f_pfs = mock_finding(
            "NO_FORWARD_SECRECY",
            "Static RSA without PFS",
            FindingSeverity::High,
        );
        let drifts1 = InfrastructureDriftCorrelator::compare_assessments(
            &prev,
            &curr1,
            &[],
            &[f_pfs.clone()],
        );
        let reg1 =
            InfrastructureDriftCorrelator::extract_security_regressions(&drifts1, &[f_pfs.clone()]);

        let now = OffsetDateTime::now_utc();
        let inv1 = InfrastructureDriftCorrelator::correlate_or_enrich_investigation(
            None,
            curr1.asset_ids[0],
            "example.com",
            &reg1,
            &[f_pfs.clone()],
            now,
        )
        .expect("Must create initial investigation");

        assert_eq!(inv1.status, InvestigationStatus::Open);
        assert_eq!(inv1.risk, RiskLevel::High);
        assert_eq!(inv1.priority, PriorityLevel::High);

        // Later scan reveals critical regression: STARTTLS lost
        let curr2 = mock_infra_assessment("example.com", 40.0, vec![ep.clone()]);
        let f_starttls = mock_finding(
            "STARTTLS_MISSING",
            "STARTTLS Missing",
            FindingSeverity::Critical,
        );
        let drifts2 = InfrastructureDriftCorrelator::compare_assessments(
            &curr1,
            &curr2,
            &[f_pfs.clone()],
            &[f_pfs.clone(), f_starttls.clone()],
        );
        let reg2 = InfrastructureDriftCorrelator::extract_security_regressions(
            &drifts2,
            &[f_starttls.clone()],
        );

        let later = now + time::Duration::hours(6);
        let inv2 = InfrastructureDriftCorrelator::correlate_or_enrich_investigation(
            Some(&inv1),
            curr2.asset_ids[0],
            "example.com",
            &reg2,
            &[f_starttls.clone()],
            later,
        )
        .expect("Must enrich existing investigation");

        assert_eq!(
            inv2.id, inv1.id,
            "Case ID must be preserved during enrichment"
        );
        assert_eq!(
            inv2.risk,
            RiskLevel::Critical,
            "Risk must be elevated to Critical"
        );
        assert_eq!(
            inv2.priority,
            PriorityLevel::Immediate,
            "Priority must be elevated to Immediate"
        );
        assert!(inv2.finding_ids.contains(&"STARTTLS_MISSING".to_string()));
        assert!(inv2.finding_ids.contains(&"NO_FORWARD_SECRECY".to_string()));
        assert_eq!(inv2.last_observed, later);
    }

    #[test]
    fn test_investigation_deduplication_on_repeated_scheduled_scans() {
        let ep = DiscoveredEndpoint {
            service: "smtp".into(),
            host: "mx1.example.com".into(),
            port: 25,
            priority: Some(10),
            resolved_ips: vec!["192.0.2.1".into()],
        };

        let prev = mock_infra_assessment("example.com", 90.0, vec![ep.clone()]);
        let curr = mock_infra_assessment("example.com", 50.0, vec![ep.clone()]);

        let f = mock_finding(
            "STARTTLS_MISSING",
            "STARTTLS Missing",
            FindingSeverity::Critical,
        );
        let drifts =
            InfrastructureDriftCorrelator::compare_assessments(&prev, &curr, &[], &[f.clone()]);
        let regressions =
            InfrastructureDriftCorrelator::extract_security_regressions(&drifts, &[f.clone()]);

        let t0 = OffsetDateTime::now_utc();
        let inv = InfrastructureDriftCorrelator::correlate_or_enrich_investigation(
            None,
            curr.asset_ids[0],
            "example.com",
            &regressions,
            &[f.clone()],
            t0,
        )
        .unwrap();

        // Repeated scan 1 hour later with the same unresolved issue
        let t1 = t0 + time::Duration::hours(1);
        let inv_scan2 = InfrastructureDriftCorrelator::correlate_or_enrich_investigation(
            Some(&inv),
            curr.asset_ids[0],
            "example.com",
            &regressions,
            &[f.clone()],
            t1,
        )
        .unwrap();
        assert_eq!(
            inv_scan2.id, inv.id,
            "Scan 2 must NOT create a duplicate investigation"
        );
        assert_eq!(
            inv_scan2.drift_event_ids.len(),
            inv.drift_event_ids.len(),
            "Drift IDs must not be duplicated"
        );

        // Repeated scan 2 hours later with the same unresolved issue
        let t2 = t0 + time::Duration::hours(2);
        let inv_scan3 = InfrastructureDriftCorrelator::correlate_or_enrich_investigation(
            Some(&inv_scan2),
            curr.asset_ids[0],
            "example.com",
            &regressions,
            &[f.clone()],
            t2,
        )
        .unwrap();
        assert_eq!(
            inv_scan3.id, inv.id,
            "Scan 3 must NOT create a duplicate investigation"
        );
        assert_eq!(inv_scan3.last_observed, t2);
    }

    #[test]
    fn test_benign_drift_creates_no_investigation() {
        let ep1 = DiscoveredEndpoint {
            service: "smtp".into(),
            host: "mx1.example.com".into(),
            port: 25,
            priority: Some(10),
            resolved_ips: vec!["192.0.2.1".into()],
        };
        let ep2 = DiscoveredEndpoint {
            service: "smtp".into(),
            host: "mx2.example.com".into(),
            port: 25,
            priority: Some(20),
            resolved_ips: vec!["192.0.2.2".into()],
        };

        let prev = mock_infra_assessment("example.com", 95.0, vec![ep1.clone()]);
        let curr = mock_infra_assessment("example.com", 95.0, vec![ep1.clone(), ep2.clone()]);

        // Routine MX addition without any policy findings
        let drifts = InfrastructureDriftCorrelator::compare_assessments(&prev, &curr, &[], &[]);
        assert!(
            !drifts.is_empty(),
            "Drift events should be detected for MX addition"
        );
        assert!(drifts.iter().any(|d| d.kind == DriftKind::EndpointAdded));

        let regressions = InfrastructureDriftCorrelator::extract_security_regressions(&drifts, &[]);
        assert!(
            regressions.is_empty(),
            "Routine MX addition must not be marked as a regression"
        );

        let now = OffsetDateTime::now_utc();
        let inv = InfrastructureDriftCorrelator::correlate_or_enrich_investigation(
            None,
            curr.asset_ids[0],
            "example.com",
            &regressions,
            &[],
            now,
        );

        assert!(
            inv.is_none(),
            "Benign drift must remain drift/history only and NEVER create an investigation"
        );
    }
}
