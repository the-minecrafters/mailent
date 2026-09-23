use std::sync::Arc;
use std::time::Duration;

use mailent_domain::{
    AssessmentSource, DnssecState, MtaStsMode, MtaStsPolicy, MxRecord, TlsRptPolicy,
};
use mailent_integrations::{MockDomainIntelligenceResolver, SrvRecord};
use mailent_probe::ProbeLimits;
use mailent_scanner::{DomainScanner, DomainScannerConfig, ScannerError};
use time::OffsetDateTime;

#[tokio::test]
async fn test_scanner_invalid_domains() {
    let resolver = Arc::new(MockDomainIntelligenceResolver::new());
    let scanner = DomainScanner::new_mock(resolver);

    assert!(matches!(
        scanner.scan_domain("").await,
        Err(ScannerError::InvalidDomain(_))
    ));
    assert!(matches!(
        scanner.scan_domain("   ").await,
        Err(ScannerError::InvalidDomain(_))
    ));
    assert!(matches!(
        scanner.scan_domain("invalid domain with spaces.com").await,
        Err(ScannerError::InvalidDomain(_))
    ));
    assert!(matches!(
        scanner.scan_domain("nodot").await,
        Err(ScannerError::InvalidDomain(_))
    ));
}

#[tokio::test]
async fn test_scanner_mock_infrastructure_and_partial_failure() {
    let resolver = Arc::new(MockDomainIntelligenceResolver::new());
    let now = OffsetDateTime::now_utc();

    // Setup MX records
    resolver
        .add_mx(
            "example.com",
            vec![
                MxRecord {
                    domain: "example.com".to_string(),
                    priority: 10,
                    hostname: "mail1.example.com".to_string(),
                    resolved_ips: vec!["192.0.2.1".to_string()],
                    dnssec: DnssecState::Insecure,
                    first_seen: now,
                    last_checked: now,
                },
                MxRecord {
                    domain: "example.com".to_string(),
                    priority: 20,
                    hostname: "mail2.example.com".to_string(),
                    resolved_ips: vec!["192.0.2.2".to_string()],
                    dnssec: DnssecState::Insecure,
                    first_seen: now,
                    last_checked: now,
                },
            ],
        )
        .await;

    // Setup MTA-STS policy
    resolver
        .add_mta_sts(
            "example.com",
            MtaStsPolicy {
                domain: "example.com".to_string(),
                version: "STSv1".to_string(),
                mode: MtaStsMode::Enforce,
                mx_patterns: vec!["mail*.example.com".to_string()],
                max_age_seconds: 86400,
                dnssec: DnssecState::Secure,
                checked_at: now,
            },
        )
        .await;

    // Setup TLS-RPT policy
    resolver
        .add_tls_rpt(
            "example.com",
            TlsRptPolicy {
                domain: "example.com".to_string(),
                rua: vec!["mailto:tls-reports@example.com".to_string()],
                checked_at: now,
            },
        )
        .await;

    // Setup SRV submission service
    resolver
        .add_srv(
            "submission",
            "tcp",
            "example.com",
            vec![SrvRecord {
                service: "submission".to_string(),
                protocol: "tcp".to_string(),
                domain: "example.com".to_string(),
                priority: 0,
                weight: 1,
                port: 587,
                target: "smtp.example.com".to_string(),
                dnssec: DnssecState::Insecure,
            }],
        )
        .await;

    // Use fast timeout so unreachable mock hosts don't stall test
    let config = DomainScannerConfig {
        probe_limits: ProbeLimits {
            connect_timeout: Duration::from_millis(50),
            read_timeout: Duration::from_millis(100),
            ..Default::default()
        },
        ..Default::default()
    };

    let scanner = DomainScanner::new(resolver, config);
    let result = scanner
        .scan_domain("example.com")
        .await
        .expect("Scan should complete even if endpoints are unreachable");

    // Verify assessment model
    match &result.assessment.source {
        AssessmentSource::Infrastructure(meta) => {
            assert_eq!(meta.target_domain, "example.com");
            assert!(meta.discovered_endpoints.len() >= 3); // 2 MX + 1 SRV
            assert!(!meta.discovery_evidence.is_empty());
        }
        _ => panic!("Expected Infrastructure assessment source"),
    }

    assert_eq!(result.endpoints_checked, 3);
    assert_eq!(result.endpoints_failed, 3); // All 3 dummy hosts failed connect
    assert_eq!(result.endpoints_succeeded, 0);

    // Verify scan survives partial failure with coverage gaps
    assert!(result.assessment.evidence_gaps.len() >= 3);
    assert!(result.assessment.posture_score <= 100.0);
    assert!(!result.assessment.posture_grade.is_empty());

    // Verify report generation
    let report = &result.report;
    assert_eq!(
        report.metadata.title,
        "example.com Mail Infrastructure Forensic Report"
    );
    assert_eq!(
        report.metadata.assessment_source.as_deref(),
        Some("infrastructure")
    );
    assert_eq!(
        report.metadata.target_domain.as_deref(),
        Some("example.com")
    );

    let infra = report
        .infrastructure
        .as_ref()
        .expect("Infrastructure section must be present");
    assert_eq!(infra.domain, "example.com");
    assert_eq!(infra.mx_records.len(), 2);
    assert_eq!(infra.discovered_endpoints.len(), 3);
    assert_eq!(infra.mta_sts_mode.as_deref(), Some("Enforce"));
    assert_eq!(
        infra.tls_rpt_destination.as_deref(),
        Some("mailto:tls-reports@example.com")
    );

    // Verify report exports
    let json = mailent_reporting::to_json(report).expect("JSON export must succeed");
    assert!(json.contains("example.com"));
    assert!(json.contains("infrastructure"));

    let html = mailent_reporting::render_html(report).expect("HTML export must succeed");
    assert!(html.starts_with("<!DOCTYPE html>"));
    assert!(html.contains("example.com"));
    assert!(html.contains("Mail Infrastructure"));

    let pdf = mailent_reporting::render_pdf(report).expect("PDF export must succeed");
    assert!(pdf.starts_with(b"%PDF-"));
    assert!(!pdf.is_empty());
}
