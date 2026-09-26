use std::sync::Arc;
use std::time::Duration;

use mailent_domain::DnssecState;
use mailent_integrations::{MockDomainIntelligenceResolver, SrvRecord};
use mailent_probe::ProbeLimits;
use mailent_scanner::{DomainScanner, DomainScannerConfig};

#[tokio::test]
async fn test_scanner_real_controlled_lab() {
    // Check if lab container is reachable on port 12525
    if tokio::net::TcpStream::connect("127.0.0.1:12525")
        .await
        .is_err()
    {
        eprintln!("Controlled lab not running on port 12525; skipping live socket verification");
        return;
    }

    let resolver = Arc::new(MockDomainIntelligenceResolver::new());

    // Map mail services to the active lab container ports via RFC 6186 SRV discovery
    resolver
        .add_srv(
            "submission",
            "tcp",
            "mailent.test",
            vec![SrvRecord {
                service: "submission".to_string(),
                protocol: "tcp".to_string(),
                domain: "mailent.test".to_string(),
                priority: 10,
                weight: 1,
                port: 12525,
                target: "127.0.0.1".to_string(),
                dnssec: DnssecState::Insecure,
            }],
        )
        .await;

    resolver
        .add_srv(
            "imaps",
            "tcp",
            "mailent.test",
            vec![SrvRecord {
                service: "imaps".to_string(),
                protocol: "tcp".to_string(),
                domain: "mailent.test".to_string(),
                priority: 20,
                weight: 1,
                port: 12993,
                target: "127.0.0.1".to_string(),
                dnssec: DnssecState::Insecure,
            }],
        )
        .await;

    let config = DomainScannerConfig {
        probe_limits: ProbeLimits {
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(5),
            ..Default::default()
        },
        ..Default::default()
    };

    let scanner = DomainScanner::new(resolver, config);
    let result = scanner
        .scan_domain("mailent.test")
        .await
        .expect("Scan against controlled lab must succeed");

    assert!(result.endpoints_checked >= 2);
    assert!(result.endpoints_succeeded >= 1);

    // Verify infrastructure report contents
    let infra = result.report.infrastructure.as_ref().unwrap();
    let submission_ep = infra
        .discovered_endpoints
        .iter()
        .find(|e| e.port == 12525)
        .expect("Submission endpoint on port 12525 must be present");

    assert_eq!(submission_ep.starttls_status, "Advertised & Accepted");
    assert!(submission_ep.tls_version.is_some());
    assert!(submission_ep.cipher.is_some());

    // Verify certificate inspection from live Postfix
    let has_cert_info = submission_ep.cert_validity.is_some() || submission_ep.cert_subject.is_some();
    assert!(
        has_cert_info,
        "Controlled lab certificate info must be inspected and present"
    );

    // Verify report exports
    let json = mailent_reporting::to_json(&result.report).unwrap();
    assert!(json.contains("mailent.test"));
    assert!(json.contains("CERTIFICATE_EXPIRED"));

    let html = mailent_reporting::render_html(&result.report).unwrap();
    assert!(html.starts_with("<!DOCTYPE html>"));
    assert!(html.contains("mailent.test"));

    let pdf = mailent_reporting::render_pdf(&result.report).unwrap();
    assert!(pdf.starts_with(b"%PDF-"));
}
