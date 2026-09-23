use std::sync::Arc;
use std::time::Duration;

use mailent_correlation::{FindingCorrelator, PostureInput, build_guidance, compute_posture};
use mailent_domain::{
    AssessmentRecord, DiscoveredEndpoint, DiscoveryEvidence, EmailProtocol, EmailSession, Finding,
    FindingCandidate, FindingCategory, FindingSeverity, InfrastructureMetadata, NetworkFlow,
    ObservationProvenance, PostureGrade, PostureSubjectKind, ProbeResult, ProbeStartTlsResult,
    ProtocolEvidence, StartTlsState,
};
use mailent_integrations::{
    DomainIntelligenceResolver, LiveDomainIntelligenceResolver, MockDomainIntelligenceResolver,
};
use mailent_policy::PolicyPack;
use mailent_probe::{ProbeLimits, ProbeScope};
use mailent_reporting::builder::{ReportInput, build_report};
use mailent_reporting::model::{DiscoveredServiceReport, ForensicReport, InfrastructureSection};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum ScannerError {
    #[error("invalid target domain: {0}")]
    InvalidDomain(String),
    #[error("resolution error: {0}")]
    Resolution(String),
    #[error("probe error: {0}")]
    Probe(String),
}

#[derive(Debug, Clone)]
pub struct DomainScannerConfig {
    pub probe_limits: ProbeLimits,
    pub policy_pack: PolicyPack,
    pub sensor_hostname: String,
}

impl Default for DomainScannerConfig {
    fn default() -> Self {
        Self {
            probe_limits: ProbeLimits {
                connect_timeout: Duration::from_secs(5),
                read_timeout: Duration::from_secs(10),
                ..Default::default()
            },
            policy_pack: PolicyPack::modern(),
            sensor_hostname: "scanner.mailent.local".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureScanResult {
    pub assessment: AssessmentRecord,
    pub report: ForensicReport,
    #[serde(default)]
    pub findings: Vec<Finding>,
    pub endpoints_checked: usize,
    pub endpoints_succeeded: usize,
    pub endpoints_failed: usize,
}

pub struct DomainScanner {
    resolver: Arc<dyn DomainIntelligenceResolver>,
    config: DomainScannerConfig,
}

impl DomainScanner {
    pub fn new(resolver: Arc<dyn DomainIntelligenceResolver>, config: DomainScannerConfig) -> Self {
        Self { resolver, config }
    }

    pub fn new_live() -> Result<Self, ScannerError> {
        let resolver = LiveDomainIntelligenceResolver::new()
            .map_err(|e| ScannerError::Resolution(e.to_string()))?;
        Ok(Self::new(
            Arc::new(resolver),
            DomainScannerConfig::default(),
        ))
    }

    pub fn new_mock(resolver: Arc<MockDomainIntelligenceResolver>) -> Self {
        Self::new(resolver, DomainScannerConfig::default())
    }

    pub async fn scan_domain(
        &self,
        target: &str,
    ) -> Result<InfrastructureScanResult, ScannerError> {
        let domain = sanitize_domain(target)?;
        let scan_start = OffsetDateTime::now_utc();

        // 1. DNS & Service Discovery
        let mut discovery_evidence = Vec::new();
        let mut discovered_endpoints: Vec<DiscoveredEndpoint> = Vec::new();

        // Query MX records
        let mx_records = self.resolver.fetch_mx(&domain).await.unwrap_or_default();

        let dnssec_state = mx_records
            .first()
            .map(|m| format!("{:?}", m.dnssec))
            .unwrap_or_else(|| "insecure".to_string());

        discovery_evidence.push(DiscoveryEvidence {
            record_type: "MX".to_string(),
            query: domain.clone(),
            details: format!("{} MX records discovered", mx_records.len()),
            dnssec_status: dnssec_state.clone(),
        });

        let mut has_null_mx = false;
        for mx in &mx_records {
            let host_clean = mx.hostname.trim_matches('.').to_string();
            if host_clean.is_empty() {
                has_null_mx = true;
                discovery_evidence.push(DiscoveryEvidence {
                    record_type: "MX".to_string(),
                    query: domain.clone(),
                    details:
                        "Explicit Null MX record published (RFC 7505: domain does not accept email)"
                            .to_string(),
                    dnssec_status: dnssec_state.clone(),
                });
                continue;
            }
            discovered_endpoints.push(DiscoveredEndpoint {
                service: "SMTP".to_string(),
                host: host_clean,
                port: 25,
                priority: Some(mx.priority),
                resolved_ips: Vec::new(),
            });
        }

        // If no MX records found and not an explicit Null MX, fall back to domain on port 25
        if discovered_endpoints.is_empty() && !has_null_mx {
            discovered_endpoints.push(DiscoveredEndpoint {
                service: "SMTP".to_string(),
                host: domain.clone(),
                port: 25,
                priority: Some(10),
                resolved_ips: Vec::new(),
            });
        }

        // Standards-based mail service discovery via SRV (RFC 6186)
        let srv_services = [
            ("submission", "tcp", 587, "SUBMISSION"),
            ("submissions", "tcp", 465, "SUBMISSIONS"),
            ("imaps", "tcp", 993, "IMAPS"),
            ("imap", "tcp", 143, "IMAP"),
            ("pop3s", "tcp", 995, "POP3S"),
            ("pop3", "tcp", 110, "POP3"),
        ];

        for (srv_name, srv_proto, _fallback_port, service_label) in srv_services {
            if let Ok(records) = self.resolver.fetch_srv(srv_name, srv_proto, &domain).await
                && !records.is_empty()
            {
                discovery_evidence.push(DiscoveryEvidence {
                    record_type: "SRV".to_string(),
                    query: format!("_{srv_name}._{srv_proto}.{domain}"),
                    details: format!("{} SRV records discovered", records.len()),
                    dnssec_status: dnssec_state.clone(),
                });
                for rec in records {
                    discovered_endpoints.push(DiscoveredEndpoint {
                        service: service_label.to_string(),
                        host: rec.target,
                        port: rec.port,
                        priority: Some(rec.priority),
                        resolved_ips: Vec::new(),
                    });
                }
            }
        }

        // Deduplicate endpoints by (host, port)
        discovered_endpoints.sort_by(|a, b| (&a.host, a.port).cmp(&(&b.host, b.port)));
        discovered_endpoints.dedup_by(|a, b| a.host == b.host && a.port == b.port);

        // Resolve IP addresses for each discovered host
        for ep in &mut discovered_endpoints {
            if let Ok(ips) = self.resolver.resolve_ips(&ep.host).await {
                ep.resolved_ips = ips;
            }
        }

        // 2. Fetch External Policies: MTA-STS, TLS-RPT, DANE
        let mta_sts_policy = self.resolver.fetch_mta_sts(&domain).await.ok().flatten();

        let tls_rpt_policy = self
            .resolver
            .fetch_tls_rpt_policy(&domain)
            .await
            .ok()
            .flatten();

        // 3. Probing Discovered Endpoints
        let mut allowed_targets = vec![mailent_probe::AuthorizedDomain {
            domain: domain.clone(),
            authorization_ref: "operator_scan".to_string(),
        }];
        for ep in &discovered_endpoints {
            allowed_targets.push(mailent_probe::AuthorizedDomain {
                domain: ep.host.clone(),
                authorization_ref: "discovered_endpoint".to_string(),
            });
            for ip in &ep.resolved_ips {
                allowed_targets.push(mailent_probe::AuthorizedDomain {
                    domain: ip.clone(),
                    authorization_ref: "resolved_ip".to_string(),
                });
            }
        }
        let scope = ProbeScope::new(allowed_targets);

        let mut probe_results = Vec::new();
        let mut endpoint_reports = Vec::new();
        let mut coverage_gaps = Vec::new();
        let mut endpoints_succeeded = 0;
        let mut endpoints_failed = 0;

        for ep in &discovered_endpoints {
            let res = match ep.service.as_str() {
                "SMTP" | "SUBMISSION" => {
                    mailent_probe::probe_smtp_starttls(
                        &ep.host,
                        ep.port,
                        &self.config.sensor_hostname,
                        &self.config.probe_limits,
                        &scope,
                    )
                    .await
                }
                "IMAP" => {
                    mailent_probe::probe_imap_starttls(
                        &ep.host,
                        ep.port,
                        &self.config.probe_limits,
                        &scope,
                    )
                    .await
                }
                "POP3" => {
                    mailent_probe::probe_pop3_stls(
                        &ep.host,
                        ep.port,
                        &self.config.probe_limits,
                        &scope,
                    )
                    .await
                }
                "SMTPS" | "SUBMISSIONS" | "IMAPS" | "POP3S" => {
                    mailent_probe::probe_implicit_tls(
                        &ep.host,
                        ep.port,
                        &self.config.probe_limits,
                        &scope,
                    )
                    .await
                }
                _ => match ep.port {
                    25 | 587 => {
                        mailent_probe::probe_smtp_starttls(
                            &ep.host,
                            ep.port,
                            &self.config.sensor_hostname,
                            &self.config.probe_limits,
                            &scope,
                        )
                        .await
                    }
                    143 => {
                        mailent_probe::probe_imap_starttls(
                            &ep.host,
                            ep.port,
                            &self.config.probe_limits,
                            &scope,
                        )
                        .await
                    }
                    110 => {
                        mailent_probe::probe_pop3_stls(
                            &ep.host,
                            ep.port,
                            &self.config.probe_limits,
                            &scope,
                        )
                        .await
                    }
                    _ => {
                        mailent_probe::probe_implicit_tls(
                            &ep.host,
                            ep.port,
                            &self.config.probe_limits,
                            &scope,
                        )
                        .await
                    }
                },
            };

            let probe_outcome = match res {
                Ok(r) => {
                    endpoints_succeeded += 1;
                    r
                }
                Err(mailent_probe::SmtpProbeError::Partial { source, evidence }) => {
                    if evidence.starttls == ProbeStartTlsResult::NotReached {
                        endpoints_failed += 1;
                        coverage_gaps.push(format!(
                            "Endpoint {}:{} check failed: {source}",
                            ep.host, ep.port
                        ));
                    } else {
                        endpoints_succeeded += 1;
                    }
                    *evidence
                }
                Err(err) => {
                    endpoints_failed += 1;
                    coverage_gaps.push(format!(
                        "Endpoint {}:{} check failed: {err}",
                        ep.host, ep.port
                    ));
                    let mut unavail = ProbeResult::unavailable(&ep.host, None);
                    unavail.error = Some(err.to_string());
                    unavail
                }
            };

            // DANE check if MX
            let mut dane_status = "not_configured".to_string();
            if ep.port == 25
                && let Ok(tlsa) = self.resolver.fetch_tlsa(&ep.host, 25).await
                && !tlsa.is_empty()
            {
                dane_status = format!("{} TLSA records published", tlsa.len());
            }

            let starttls_str = match probe_outcome.starttls {
                ProbeStartTlsResult::AdvertisedAndAccepted => "Advertised & Accepted".to_string(),
                ProbeStartTlsResult::AdvertisedAndRejected => "Advertised & Rejected".to_string(),
                ProbeStartTlsResult::NotAdvertised => "Not Advertised".to_string(),
                ProbeStartTlsResult::AcceptedHandshakeFailed => {
                    "Accepted (TLS Handshake Failed)".to_string()
                }
                ProbeStartTlsResult::ImplicitTls => "Implicit TLS".to_string(),
                ProbeStartTlsResult::NotReached => probe_outcome
                    .error
                    .clone()
                    .unwrap_or_else(|| "Unavailable".to_string()),
            };

            let (cert_sub, cert_iss, cert_val) = if let Some(cert) = &probe_outcome.certificate {
                (
                    Some(cert.reference.subject.clone()),
                    Some(cert.reference.issuer.clone()),
                    Some(format!(
                        "valid {} → {}",
                        cert.validity.not_before, cert.validity.not_after
                    )),
                )
            } else {
                (None, None, None)
            };

            endpoint_reports.push(DiscoveredServiceReport {
                service: ep.service.clone(),
                host: ep.host.clone(),
                port: ep.port,
                priority: ep.priority,
                resolved_ips: ep.resolved_ips.clone(),
                starttls_status: starttls_str,
                tls_version: probe_outcome.tls_version.as_ref().map(|v| v.to_string()),
                cipher: probe_outcome.cipher_suite.as_ref().map(|c| c.name.clone()),
                cert_subject: cert_sub,
                cert_issuer: cert_iss,
                cert_validity: cert_val,
                dane_status,
            });

            probe_results.push((ep.clone(), probe_outcome));
        }

        // 4. Session & Policy Findings Evaluation
        let mut sessions = Vec::new();
        let mut all_findings: Vec<Finding> = Vec::new();
        let mut protocols_set = std::collections::BTreeSet::new();
        let mut protocol_evidence = Vec::new();

        let asset_id = Uuid::new_v5(&Uuid::NAMESPACE_OID, domain.as_bytes());

        for (ep, probe) in &probe_results {
            let proto = match ep.port {
                25 | 587 => EmailProtocol::Smtp,
                143 | 993 => EmailProtocol::Imap,
                110 | 995 => EmailProtocol::Pop3,
                _ => EmailProtocol::Smtp,
            };
            protocols_set.insert(format!("{:?}", proto));

            protocol_evidence.push(ProtocolEvidence {
                protocol: format!("{:?}", proto),
                role: "server".to_string(),
                proof: format!(
                    "Endpoint {}:{} returned banner/TLS handshake",
                    ep.host, ep.port
                ),
                verified_by: "mailent-probe".to_string(),
            });

            let session = probe_to_session(probe, proto, ep.port, &domain);
            let mut candidates = mailent_policy::evaluate(&session, &self.config.policy_pack);

            // Synthesize external policy findings where applicable
            if mta_sts_policy.is_none() && ep.port == 25 {
                candidates.push(FindingCandidate {
                    rule_id: "MTA_STS_POLICY_MISSING".to_string(),
                    policy_name: self.config.policy_pack.name.clone(),
                    policy_version: self.config.policy_pack.version.clone(),
                    severity: FindingSeverity::Medium,
                    category: FindingCategory::PolicyViolation,
                    title: "MTA-STS Policy Not Published".to_string(),
                    description: format!(
                        "Domain {} does not publish an MTA-STS policy (RFC 8461) at https://mta-sts.{}/.well-known/mta-sts.txt",
                        domain, domain
                    ),
                    remediation: "Deploy and publish an MTA-STS policy to enforce TLS and protect against downgrade attacks.".to_string(),
                    reference: "rfc8461".to_string(),
                    evidence: vec![],
                });
            }

            if tls_rpt_policy.is_none() && ep.port == 25 {
                candidates.push(FindingCandidate {
                    rule_id: "TLS_RPT_POLICY_MISSING".to_string(),
                    policy_name: self.config.policy_pack.name.clone(),
                    policy_version: self.config.policy_pack.version.clone(),
                    severity: FindingSeverity::Low,
                    category: FindingCategory::PolicyViolation,
                    title: "TLS-RPT Policy Not Published".to_string(),
                    description: format!(
                        "Domain {} does not publish a TLS-RPT DNS record (RFC 8460) at _smtp._tls.{}",
                        domain, domain
                    ),
                    remediation: "Publish a TXT record at _smtp._tls to receive automated diagnostic reports for TLS negotiation failures.".to_string(),
                    reference: "rfc8460".to_string(),
                    evidence: vec![],
                });
            }

            let correlated = FindingCorrelator::correlate_session(&session, &candidates);
            all_findings.extend(correlated);
            sessions.push(session);
        }

        // Deduplicate findings by rule_id and title
        all_findings.sort_by(|a, b| (&a.rule_id, &a.title).cmp(&(&b.rule_id, &b.title)));
        all_findings.dedup_by(|a, b| a.rule_id == b.rule_id && a.title == b.title);

        // 5. Posture Calculation
        let scan_end = OffsetDateTime::now_utc();
        let posture_input = PostureInput {
            findings: &all_findings,
            anomalies: &[],
            asset: None,
            asset_sessions: &sessions,
            certificates: &[],
            probe_runs: &[],
            investigation: None,
        };
        let posture = compute_posture(PostureSubjectKind::Asset, asset_id, &posture_input);
        let guidance = build_guidance(asset_id, &all_findings, None, &sessions, &[], scan_end);

        let posture_score = posture.score;
        let posture_grade = posture.grade.to_string();

        let ai_risk_classification = match posture.grade {
            PostureGrade::Strong | PostureGrade::Good => "LOW".to_string(),
            PostureGrade::Moderate => "MEDIUM".to_string(),
            PostureGrade::Weak => "HIGH".to_string(),
            PostureGrade::Critical => "CRITICAL".to_string(),
        };

        let ai_risk_rationale = format!(
            "Infrastructure posture score is {:.1}/100 (Grade {}). Discovered {} endpoints ({} healthy, {} failed). {} findings identified across TLS, certificate, and external policy configurations.",
            posture_score,
            posture_grade,
            discovered_endpoints.len(),
            endpoints_succeeded,
            endpoints_failed,
            all_findings.len()
        );

        // 6. Build AssessmentRecord
        let infra_metadata = InfrastructureMetadata {
            target_domain: domain.clone(),
            discovered_endpoints: discovered_endpoints.clone(),
            scan_start,
            scan_end,
            discovery_evidence,
        };

        let assessment_id = Uuid::new_v4();
        let session_ids = sessions.iter().map(|s| s.session_id).collect();
        let finding_ids = all_findings.iter().map(|f| f.id).collect();

        let assessment = AssessmentRecord::new_infrastructure(
            assessment_id,
            format!("{} Infrastructure Assessment", domain),
            infra_metadata,
            scan_end,
            protocols_set.into_iter().collect(),
            protocol_evidence,
            session_ids,
            vec![asset_id],
            finding_ids,
            posture_score,
            posture_grade,
            coverage_gaps.clone(),
            ai_risk_classification,
            ai_risk_rationale,
            0.0,
            serde_json::json!({
                "scanner": "mailent-scanner",
                "version": "0.1.0",
                "target_domain": domain,
                "endpoints_checked": discovered_endpoints.len(),
                "endpoints_succeeded": endpoints_succeeded,
                "endpoints_failed": endpoints_failed,
            }),
        );

        // 7. Build ForensicReport
        let mta_sts_mode = mta_sts_policy.as_ref().map(|p| format!("{:?}", p.mode));
        let mta_sts_details = mta_sts_policy.as_ref().map(|p| {
            format!(
                "mode: {:?}, max_age: {}, mx: [{}]",
                p.mode,
                p.max_age_seconds,
                p.mx_patterns.join(", ")
            )
        });
        let tls_rpt_dest = tls_rpt_policy.as_ref().map(|p| p.rua.join(", "));

        let infra_section = InfrastructureSection {
            domain: domain.clone(),
            mx_records: mx_records
                .iter()
                .map(|m| format!("{} (pref: {})", m.hostname, m.priority))
                .collect(),
            discovered_endpoints: endpoint_reports,
            mta_sts_mode,
            mta_sts_policy_details: mta_sts_details,
            tls_rpt_destination: tls_rpt_dest,
            dnssec_status: dnssec_state,
        };

        let report_input = ReportInput {
            investigation: None,
            asset: None,
            sessions: &sessions,
            findings: &all_findings,
            anomalies: &[],
            drifts: &[],
            probe_runs: &[],
            posture: Some(&posture),
            guidance: &guidance,
            remediation_records: &[],
            policy_name: self.config.policy_pack.name.clone(),
            policy_version: self.config.policy_pack.version.clone(),
            assessment_source: Some("infrastructure".to_string()),
            target_domain: Some(domain.clone()),
            infrastructure: Some(infra_section),
        };

        let report = build_report(
            format!("{} Mail Infrastructure Forensic Report", domain),
            "0.1.0",
            &report_input,
            scan_end,
        );

        Ok(InfrastructureScanResult {
            assessment,
            report,
            findings: all_findings,
            endpoints_checked: discovered_endpoints.len(),
            endpoints_succeeded,
            endpoints_failed,
        })
    }
}

fn sanitize_domain(raw: &str) -> Result<String, ScannerError> {
    let clean = raw
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .trim_end_matches('.')
        .to_lowercase();

    if clean.is_empty() {
        return Err(ScannerError::InvalidDomain("Domain cannot be empty".into()));
    }
    if clean.contains(' ') || clean.contains('/') || clean.contains(':') {
        return Err(ScannerError::InvalidDomain(format!(
            "Invalid domain format: '{raw}'"
        )));
    }
    if !clean.contains('.') {
        return Err(ScannerError::InvalidDomain(format!(
            "Domain must contain a valid TLD: '{raw}'"
        )));
    }
    Ok(clean)
}

fn probe_to_session(
    probe: &ProbeResult,
    protocol: EmailProtocol,
    port: u16,
    _domain: &str,
) -> EmailSession {
    let now = OffsetDateTime::now_utc();
    let starttls_state = match probe.starttls {
        ProbeStartTlsResult::AdvertisedAndAccepted => Some(StartTlsState::AdvertisedAndUsed),
        ProbeStartTlsResult::AdvertisedAndRejected => Some(StartTlsState::Rejected),
        ProbeStartTlsResult::NotAdvertised => Some(StartTlsState::NotAdvertised),
        ProbeStartTlsResult::AcceptedHandshakeFailed => Some(StartTlsState::FailedHandshake),
        ProbeStartTlsResult::ImplicitTls => Some(StartTlsState::TlsEstablished),
        ProbeStartTlsResult::NotReached => None,
    };

    let key_exchange_model = match probe.forward_secrecy {
        mailent_domain::ForwardSecrecyState::Supported => Some(mailent_domain::KeyExchange::Ecdhe),
        mailent_domain::ForwardSecrecyState::NotSupported => {
            Some(mailent_domain::KeyExchange::RsaStatic)
        }
        mailent_domain::ForwardSecrecyState::Unknown => None,
    };

    EmailSession {
        session_id: Uuid::new_v4(),
        sensor_id: "mailent-scanner".to_string(),
        provenance: ObservationProvenance {
            source: "scanner".to_string(),
            parser: "mailent-probe".to_string(),
            parser_version: "0.1.0".to_string(),
        },
        flow: NetworkFlow {
            src_ip: "127.0.0.1".into(),
            src_port: 0,
            dst_ip: probe
                .resolved_ip
                .clone()
                .unwrap_or_else(|| probe.resolved_host.clone()),
            dst_port: port,
        },
        protocol,
        starttls_state,
        tls_version: probe.tls_version.clone(),
        cipher_suite: probe.cipher_suite.clone(),
        key_exchange: key_exchange_model,
        certificate: probe.certificate.clone(),
        capture: None,
        first_seen: now,
        last_seen: now,
    }
}
