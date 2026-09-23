use mailent_domain::{AnomalySignal, AssetBaseline, DaneStatus, EmailSession, StartTlsState};
use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

pub trait BaselineAnalyzer: Send + Sync {
    fn compute_baseline(
        &self,
        asset_id: Uuid,
        sessions: &[EmailSession],
        window_start: OffsetDateTime,
        window_end: OffsetDateTime,
    ) -> AssetBaseline;

    fn analyze_session(
        &self,
        baseline: &AssetBaseline,
        session: &EmailSession,
    ) -> Vec<AnomalySignal>;
}

#[derive(Debug, Default, Clone)]
pub struct DefaultBaselineAnalyzer;

impl DefaultBaselineAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl BaselineAnalyzer for DefaultBaselineAnalyzer {
    fn compute_baseline(
        &self,
        asset_id: Uuid,
        sessions: &[EmailSession],
        window_start: OffsetDateTime,
        window_end: OffsetDateTime,
    ) -> AssetBaseline {
        calculate_baseline(asset_id, sessions, window_start, window_end)
    }

    fn analyze_session(
        &self,
        baseline: &AssetBaseline,
        session: &EmailSession,
    ) -> Vec<AnomalySignal> {
        detect_session_anomalies(baseline, session)
    }
}

/// Constructs an AssetBaseline from a collection of historical sessions.
pub fn calculate_baseline(
    asset_id: Uuid,
    sessions: &[EmailSession],
    window_start: OffsetDateTime,
    window_end: OffsetDateTime,
) -> AssetBaseline {
    let sample_count = sessions.len() as u64;
    let mut tls_version_counts: HashMap<String, u64> = HashMap::new();
    let mut cipher_counts: HashMap<String, u64> = HashMap::new();
    let mut key_exchange_counts: HashMap<String, u64> = HashMap::new();
    let mut certificate_fingerprints: Vec<String> = Vec::new();
    let mut certificate_issuers: Vec<String> = Vec::new();
    let mut peer_set: Vec<String> = Vec::new();
    let mut ports: Vec<u16> = Vec::new();

    let mut starttls_offered_or_attempted = 0u64;
    let mut starttls_succeeded = 0u64;
    let mut handshake_failures = 0u64;

    for s in sessions {
        // Ports
        let port = s.flow.dst_port;
        if !ports.contains(&port) {
            ports.push(port);
        }

        // Peers
        let peer_ip = s.flow.src_ip.clone();
        if !peer_set.contains(&peer_ip) {
            peer_set.push(peer_ip);
        }

        // TLS Version
        if let Some(ref ver) = s.tls_version {
            *tls_version_counts.entry(ver.to_string()).or_insert(0) += 1;
        }

        // Cipher Suite
        if let Some(ref cipher) = s.cipher_suite {
            *cipher_counts.entry(cipher.name.clone()).or_insert(0) += 1;
        }

        // Key Exchange
        if let Some(ref kx) = s.key_exchange {
            let kx_name = match kx {
                mailent_domain::KeyExchange::Ecdhe => "ECDHE".to_string(),
                mailent_domain::KeyExchange::Dhe => "DHE".to_string(),
                mailent_domain::KeyExchange::RsaStatic => "RSA".to_string(),
                mailent_domain::KeyExchange::HybridPqc(pqc) => format!("HybridPQC({pqc})"),
                mailent_domain::KeyExchange::Unknown(u) => u.clone(),
            };
            *key_exchange_counts.entry(kx_name).or_insert(0) += 1;
        }

        // Certificate
        if let Some(ref cert) = s.certificate {
            if !certificate_fingerprints.contains(&cert.reference.sha256_fingerprint) {
                certificate_fingerprints.push(cert.reference.sha256_fingerprint.clone());
            }
            if !certificate_issuers.contains(&cert.reference.issuer) {
                certificate_issuers.push(cert.reference.issuer.clone());
            }
        }

        // STARTTLS tracking
        if let Some(ref st) = s.starttls_state {
            match st {
                StartTlsState::AdvertisedAndUsed
                | StartTlsState::TlsEstablished
                | StartTlsState::TlsStarted => {
                    starttls_offered_or_attempted += 1;
                    starttls_succeeded += 1;
                }
                StartTlsState::FailedHandshake | StartTlsState::Rejected => {
                    starttls_offered_or_attempted += 1;
                    handshake_failures += 1;
                }
                StartTlsState::AdvertisedNotUsed => {
                    starttls_offered_or_attempted += 1;
                }
                StartTlsState::Advertised
                | StartTlsState::Requested
                | StartTlsState::Accepted
                | StartTlsState::NotAdvertised
                | StartTlsState::PlaintextContinuation => {}
            }
        }
    }

    // Distributions
    let total_samples_f = (sample_count.max(1)) as f32;
    let mut tls_version_distribution: HashMap<String, f32> = HashMap::new();
    for (k, v) in tls_version_counts {
        tls_version_distribution.insert(k, v as f32 / total_samples_f);
    }

    let mut cipher_distribution: HashMap<String, f32> = HashMap::new();
    for (k, v) in cipher_counts {
        cipher_distribution.insert(k, v as f32 / total_samples_f);
    }

    let mut key_exchange_distribution: HashMap<String, f32> = HashMap::new();
    for (k, v) in key_exchange_counts {
        key_exchange_distribution.insert(k, v as f32 / total_samples_f);
    }

    let starttls_success_rate = if starttls_offered_or_attempted > 0 {
        starttls_succeeded as f32 / starttls_offered_or_attempted as f32
    } else {
        1.0
    };

    let handshake_failure_rate = handshake_failures as f32 / total_samples_f;

    let duration_seconds = (window_end - window_start).whole_seconds().max(1);
    let hours = duration_seconds as f32 / 3600.0;
    let session_frequency_per_hour = if hours > 0.0 {
        sample_count as f32 / hours
    } else {
        sample_count as f32
    };

    let coverage = if sample_count > 0 { 1.0 } else { 0.0 };

    AssetBaseline {
        asset_id,
        sample_count,
        window_start,
        window_end,
        generated_at: OffsetDateTime::now_utc(),
        coverage,
        tls_version_distribution,
        cipher_distribution,
        key_exchange_distribution,
        certificate_fingerprints,
        certificate_issuers,
        starttls_success_rate,
        handshake_failure_rate,
        peer_set,
        ports,
        session_frequency_per_hour,
    }
}

/// Detects candidate anomalies for a single session against an established baseline.
pub fn detect_session_anomalies(
    baseline: &AssetBaseline,
    session: &EmailSession,
) -> Vec<AnomalySignal> {
    let mut signals = Vec::new();
    let now = OffsetDateTime::now_utc();

    // 1. Unseen TLS Version (if baseline has enough samples)
    if baseline.sample_count >= 5
        && let Some(ref ver) = session.tls_version
    {
        let ver_str = ver.to_string();
        let prevalence = baseline
            .tls_version_distribution
            .get(&ver_str)
            .copied()
            .unwrap_or(0.0);

        if prevalence == 0.0 {
            let dominant = baseline
                .tls_version_distribution
                .iter()
                .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
                .map(|(k, _)| k.as_str())
                .unwrap_or("none");

            signals.push(AnomalySignal {
                id: Uuid::new_v4(),
                asset_id: baseline.asset_id,
                signal: "UnseenTlsVersion".to_string(),
                title: format!("Unseen TLS version {ver_str} observed"),
                current_value: ver_str,
                baseline_value: format!(
                    "Dominant version: {dominant} (never observed in baseline)"
                ),
                deviation: 1.0,
                confidence: 0.9,
                evidence: format!(
                    "Session {} observed TLS version not present in {} historical baseline samples",
                    session.session_id, baseline.sample_count
                ),
                observed_at: now,
            });
        }
    }

    // 2. Rare Cipher Suite (< 5% prevalence in baseline)
    if baseline.sample_count >= 5
        && let Some(ref cipher) = session.cipher_suite
    {
        let prevalence = baseline
            .cipher_distribution
            .get(&cipher.name)
            .copied()
            .unwrap_or(0.0);

        if prevalence < 0.05 {
            signals.push(AnomalySignal {
                id: Uuid::new_v4(),
                asset_id: baseline.asset_id,
                signal: "RareCipher".to_string(),
                title: format!("Rare cipher suite '{}' observed", cipher.name),
                current_value: cipher.name.clone(),
                baseline_value: format!("{:.1}% prevalence", prevalence * 100.0),
                deviation: 1.0 - prevalence,
                confidence: 0.8,
                evidence: format!(
                    "Session {} used cipher '{}' which appears in only {:.1}% of baseline samples",
                    session.session_id,
                    cipher.name,
                    prevalence * 100.0
                ),
                observed_at: now,
            });
        }
    }

    // 3. Sudden STARTTLS Success Rate Drop / Failure
    if let Some(ref st) = session.starttls_state {
        let is_failure = matches!(st, StartTlsState::FailedHandshake | StartTlsState::Rejected);

        if is_failure && baseline.starttls_success_rate > 0.7 && baseline.sample_count >= 5 {
            signals.push(AnomalySignal {
                id: Uuid::new_v4(),
                asset_id: baseline.asset_id,
                signal: "StarttlsSuccessRateDrop".to_string(),
                title: format!("STARTTLS handshake failure state: {st:?}"),
                current_value: format!("{st:?}"),
                baseline_value: format!("{:.1}% success rate", baseline.starttls_success_rate * 100.0),
                deviation: 0.95,
                confidence: 0.85,
                evidence: format!(
                    "Session {} failed STARTTLS negotiation while asset baseline has {:.1}% success rate",
                    session.session_id, baseline.starttls_success_rate * 100.0
                ),
                observed_at: now,
            });
        }
    }

    // 4. Unexpected Certificate Issuer
    if baseline.sample_count >= 3
        && let Some(ref cert) = session.certificate
    {
        let issuer = &cert.reference.issuer;
        if !baseline.certificate_issuers.is_empty()
            && !baseline.certificate_issuers.contains(issuer)
        {
            signals.push(AnomalySignal {
                id: Uuid::new_v4(),
                asset_id: baseline.asset_id,
                signal: "UnexpectedCertificateIssuer".to_string(),
                title: format!("Certificate issued by unexpected CA: {issuer}"),
                current_value: issuer.clone(),
                baseline_value: baseline.certificate_issuers.join(", "),
                deviation: 1.0,
                confidence: 0.85,
                evidence: format!(
                    "Observed certificate subject '{}' issued by '{}', not seen in baseline CAs",
                    cert.reference.subject, issuer
                ),
                observed_at: now,
            });
        }
    }

    // 5. New Peer / Client IP (when baseline has at least 10 samples)
    if baseline.sample_count >= 10 {
        let peer_ip = &session.flow.src_ip;
        if !baseline.peer_set.is_empty() && !baseline.peer_set.contains(peer_ip) {
            signals.push(AnomalySignal {
                id: Uuid::new_v4(),
                asset_id: baseline.asset_id,
                signal: "NewPeer".to_string(),
                title: format!("Traffic observed from new peer: {peer_ip}"),
                current_value: peer_ip.clone(),
                baseline_value: format!("{} known peers", baseline.peer_set.len()),
                deviation: 0.6,
                confidence: 0.65,
                evidence: format!(
                    "Source IP {} has not communicated with this mail asset in established baseline",
                    peer_ip
                ),
                observed_at: now,
            });
        }
    }

    signals
}

/// Detects intelligence and configuration anomalies (DANE mismatch, MTA-STS failure, TLS-RPT spike, internal/external inconsistency).
pub fn detect_intelligence_anomalies(
    asset_id: Uuid,
    session: &EmailSession,
    dane_status: Option<DaneStatus>,
    mta_sts_failed: bool,
    tls_rpt_failure_count: Option<u64>,
    domain_mta_sts_enforced: bool,
) -> Vec<AnomalySignal> {
    let mut signals = Vec::new();
    let now = OffsetDateTime::now_utc();

    // 1. DANE Mismatch
    if let Some(status) = dane_status
        && status == DaneStatus::DaneMismatch
    {
        signals.push(AnomalySignal {
            id: Uuid::new_v4(),
            asset_id,
            signal: "NewDaneMismatch".to_string(),
            title: "DANE TLSA record verification mismatch".to_string(),
            current_value: "Mismatch".to_string(),
            baseline_value: "Valid DANE / TLSA".to_string(),
            deviation: 1.0,
            confidence: 0.95,
            evidence: format!(
                "Observed certificate on session {} failed cryptographic TLSA matching",
                session.session_id
            ),
            observed_at: now,
        });
    }

    // 2. MTA-STS Mismatch
    if mta_sts_failed {
        signals.push(AnomalySignal {
            id: Uuid::new_v4(),
            asset_id,
            signal: "MtaStsMismatch".to_string(),
            title: "MTA-STS policy validation failed".to_string(),
            current_value: "Policy Violation".to_string(),
            baseline_value: "Compliant with MTA-STS".to_string(),
            deviation: 0.9,
            confidence: 0.9,
            evidence: format!(
                "Session {} failed MTA-STS MX host match or required TLS enforcement",
                session.session_id
            ),
            observed_at: now,
        });
    }

    // 3. TLS-RPT Failure Spike
    if let Some(count) = tls_rpt_failure_count
        && count >= 10
    {
        signals.push(AnomalySignal {
            id: Uuid::new_v4(),
            asset_id,
            signal: "TlsRptFailureSpike".to_string(),
            title: format!("TLS-RPT failure count elevated: {count} failures"),
            current_value: format!("{count} failures"),
            baseline_value: "0 failures".to_string(),
            deviation: (count as f32 / 50.0).min(1.0),
            confidence: 0.85,
            evidence: format!(
                "External senders reported {count} TLS negotiation failures via TLS-RPT JSON reports",
            ),
            observed_at: now,
        });
    }

    // 4. Internal vs External Inconsistency
    if domain_mta_sts_enforced {
        let is_plaintext = session.tls_version.is_none()
            || matches!(
                session.starttls_state,
                Some(StartTlsState::NotAdvertised)
                    | Some(StartTlsState::AdvertisedNotUsed)
                    | Some(StartTlsState::PlaintextContinuation)
            );
        if is_plaintext {
            signals.push(AnomalySignal {
                id: Uuid::new_v4(),
                asset_id,
                signal: "InternalExternalInconsistency".to_string(),
                title: "Internal unencrypted session violates external MTA-STS 'enforce'".to_string(),
                current_value: "Plaintext/Unencrypted".to_string(),
                baseline_value: "MTA-STS Enforce (External)".to_string(),
                deviation: 1.0,
                confidence: 0.95,
                evidence: format!(
                    "Domain advertises MTA-STS mode 'enforce', but session {} completed in plaintext",
                    session.session_id
                ),
                observed_at: now,
            });
        }
    }

    signals
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailent_domain::{
        CertificateObservation, CertificateReference, CipherSuite, EmailProtocol, NetworkFlow,
        ObservationProvenance, TlsVersion, ValidityPeriod,
    };
    use time::Duration;

    fn mock_session(
        tls_ver: Option<TlsVersion>,
        cipher: Option<&str>,
        issuer: Option<&str>,
        st_state: Option<StartTlsState>,
        src_ip: &str,
    ) -> EmailSession {
        let cert = issuer.map(|iss| CertificateObservation {
            reference: CertificateReference {
                sha256_fingerprint: "aabbcc112233".to_string(),
                subject: "CN=mail.example.com".to_string(),
                issuer: iss.to_string(),
            },
            validity: ValidityPeriod {
                not_before: OffsetDateTime::now_utc() - Duration::days(10),
                not_after: OffsetDateTime::now_utc() + Duration::days(80),
            },
            is_self_signed: Some(false),
            san: vec!["mail.example.com".to_string()],
        });

        EmailSession {
            session_id: Uuid::new_v4(),
            sensor_id: "test-sensor".to_string(),
            provenance: ObservationProvenance {
                source: "zeek".to_string(),
                parser: "zeek".to_string(),
                parser_version: "1.0".to_string(),
            },
            flow: NetworkFlow {
                src_ip: src_ip.to_string(),
                src_port: 54321,
                dst_ip: "192.168.1.10".to_string(),
                dst_port: 25,
            },
            protocol: EmailProtocol::Smtp,
            starttls_state: st_state,
            tls_version: tls_ver,
            cipher_suite: cipher.map(|c| CipherSuite {
                id: None,
                name: c.to_string(),
            }),
            key_exchange: None,
            certificate: cert,
            capture: None,
            first_seen: OffsetDateTime::now_utc(),
            last_seen: OffsetDateTime::now_utc(),
        }
    }

    #[test]
    fn test_baseline_calculation_and_unseen_tls_version_anomaly() {
        let asset_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let window_start = now - Duration::days(7);
        let window_end = now;

        // Build 10 sessions with TLS 1.3
        let sessions: Vec<EmailSession> = (0..10)
            .map(|_| {
                mock_session(
                    Some(TlsVersion::Tls13),
                    Some("TLS_AES_256_GCM_SHA384"),
                    Some("DigiCert Inc"),
                    Some(StartTlsState::AdvertisedAndUsed),
                    "10.0.0.5",
                )
            })
            .collect();

        let baseline = calculate_baseline(asset_id, &sessions, window_start, window_end);

        assert_eq!(baseline.sample_count, 10);
        assert_eq!(baseline.starttls_success_rate, 1.0);
        assert_eq!(
            *baseline.tls_version_distribution.get("TLSv1.3").unwrap(),
            1.0
        );
        assert!(
            baseline
                .certificate_issuers
                .contains(&"DigiCert Inc".to_string())
        );

        // Now test a session with TLS 1.0 (unseen)
        let anomaly_session = mock_session(
            Some(TlsVersion::Tls10),
            Some("TLS_RSA_WITH_AES_128_CBC_SHA"),
            Some("DigiCert Inc"),
            Some(StartTlsState::AdvertisedAndUsed),
            "10.0.0.5",
        );

        let anomalies = detect_session_anomalies(&baseline, &anomaly_session);
        assert!(anomalies.iter().any(|a| a.signal == "UnseenTlsVersion"));
        assert!(anomalies.iter().any(|a| a.signal == "RareCipher"));
    }

    #[test]
    fn test_starttls_drop_and_unexpected_issuer() {
        let asset_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let sessions: Vec<EmailSession> = (0..5)
            .map(|_| {
                mock_session(
                    Some(TlsVersion::Tls13),
                    Some("TLS_AES_256_GCM_SHA384"),
                    Some("Let's Encrypt"),
                    Some(StartTlsState::AdvertisedAndUsed),
                    "10.0.0.5",
                )
            })
            .collect();

        let baseline = calculate_baseline(asset_id, &sessions, now - Duration::days(1), now);

        let rogue_session = mock_session(
            Some(TlsVersion::Tls13),
            Some("TLS_AES_256_GCM_SHA384"),
            Some("Rogue CA Co"),
            Some(StartTlsState::FailedHandshake),
            "10.0.0.5",
        );

        let anomalies = detect_session_anomalies(&baseline, &rogue_session);
        assert!(
            anomalies
                .iter()
                .any(|a| a.signal == "StarttlsSuccessRateDrop")
        );
        assert!(
            anomalies
                .iter()
                .any(|a| a.signal == "UnexpectedCertificateIssuer")
        );
    }

    #[test]
    fn test_intelligence_anomalies() {
        let asset_id = Uuid::new_v4();
        let session = mock_session(
            None,
            None,
            None,
            Some(StartTlsState::NotAdvertised),
            "10.0.0.5",
        );

        let anomalies = detect_intelligence_anomalies(
            asset_id,
            &session,
            Some(DaneStatus::DaneMismatch),
            true,
            Some(25),
            true,
        );

        assert!(anomalies.iter().any(|a| a.signal == "NewDaneMismatch"));
        assert!(anomalies.iter().any(|a| a.signal == "MtaStsMismatch"));
        assert!(anomalies.iter().any(|a| a.signal == "TlsRptFailureSpike"));
        assert!(
            anomalies
                .iter()
                .any(|a| a.signal == "InternalExternalInconsistency")
        );
    }
}
