use crate::scope::{ProbeScope, ProbeScopeError};
use mailent_domain::{
    CertificateObservation, CertificateReference, CipherSuite, ForwardSecrecyState, ProbeResult,
    ProbeStartTlsResult, TlsVersion, ValidityPeriod,
};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use sha2::{Digest, Sha256};
use std::{
    pin::Pin,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

#[derive(Debug, thiserror::Error)]
pub enum SmtpProbeError {
    #[error("{source}")]
    Partial {
        source: Box<SmtpProbeError>,
        evidence: Box<ProbeResult>,
    },
    #[error("scope enforcement rejected target: {0}")]
    ScopeRejected(#[from] ProbeScopeError),
    #[error("probe timed out after {0}s")]
    Timeout(u64),
    #[error("connection refused")]
    ConnectionRefused,
    #[error("TLS handshake failed: {0}")]
    TlsHandshakeFailed(String),
    #[error("SMTP protocol error: {0}")]
    Protocol(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl SmtpProbeError {
    pub fn root(&self) -> &Self {
        match self {
            Self::Partial { source, .. } => source.root(),
            other => other,
        }
    }
}

pub struct ProbeLimits {
    /// Exact protocol challenge, used only by authorized remediation verification.
    pub forced_tls_version: Option<TlsVersion>,
    pub connect_timeout: Duration,
    /// Overall deadline covering DNS, connect, greeting, EHLO, and TLS.
    pub read_timeout: Duration,
    pub max_line_bytes: usize,
    pub max_exchange_lines: usize,
}
impl Default for ProbeLimits {
    fn default() -> Self {
        Self {
            forced_tls_version: None,
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(15),
            max_line_bytes: 1024,
            max_exchange_lines: 50,
        }
    }
}

/// Authorization is enforced before DNS or TCP, including for library callers.
pub async fn probe_smtp_starttls(
    host: &str,
    port: u16,
    sensor_hostname: &str,
    limits: &ProbeLimits,
    scope: &ProbeScope,
) -> Result<ProbeResult, SmtpProbeError> {
    scope.validate(host)?;
    if sensor_hostname.is_empty()
        || !sensor_hostname
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
    {
        return Err(SmtpProbeError::Protocol("invalid EHLO identity".into()));
    }
    timed_probe(host, port, Some(sensor_hostname), limits).await
}

pub async fn probe_implicit_tls(
    host: &str,
    port: u16,
    limits: &ProbeLimits,
    scope: &ProbeScope,
) -> Result<ProbeResult, SmtpProbeError> {
    scope.validate(host)?;
    timed_probe(host, port, None, limits).await
}

async fn timed_probe(
    host: &str,
    port: u16,
    ehlo: Option<&str>,
    limits: &ProbeLimits,
) -> Result<ProbeResult, SmtpProbeError> {
    let started = Instant::now();
    let mut result = ProbeResult::unavailable(host, None);
    let work = exchange(host, port, ehlo, limits, &mut result);
    let failure = match tokio::time::timeout(limits.read_timeout, work).await {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(e),
        Err(_) => Some(SmtpProbeError::Timeout(limits.read_timeout.as_secs())),
    };
    if let Some(error) = failure {
        result.error = Some(error.to_string());
        result.latency_ms = started.elapsed().as_millis() as u64;
        return Err(SmtpProbeError::Partial {
            source: Box::new(error),
            evidence: Box::new(result),
        });
    }
    result.latency_ms = started.elapsed().as_millis() as u64;
    Ok(result)
}

async fn exchange(
    host: &str,
    port: u16,
    ehlo: Option<&str>,
    limits: &ProbeLimits,
    result: &mut ProbeResult,
) -> Result<(), SmtpProbeError> {
    let stream = tokio::time::timeout(
        limits.connect_timeout,
        TcpStream::connect((host.trim_end_matches('.'), port)),
    )
    .await
    .map_err(|_| SmtpProbeError::Timeout(limits.connect_timeout.as_secs()))?
    .map_err(|e| {
        if e.kind() == std::io::ErrorKind::ConnectionRefused {
            SmtpProbeError::ConnectionRefused
        } else {
            SmtpProbeError::Io(e)
        }
    })?;
    result.resolved_ip = Some(stream.peer_addr()?.ip().to_string());
    let mut reader = BufReader::new(stream);
    if let Some(identity) = ehlo {
        let greeting = read_multiline_response(&mut reader, limits).await?;
        require_code(&greeting, "220")?;
        result.smtp_greeting = Some(greeting.join(" "));
        reader
            .get_mut()
            .write_all(format!("EHLO {identity}\r\n").as_bytes())
            .await?;
        let capabilities = read_multiline_response(&mut reader, limits).await?;
        require_code(&capabilities, "250")?;
        result.ehlo_capabilities = capabilities
            .iter()
            .filter_map(|l| l.get(4..))
            .map(str::to_owned)
            .collect();
        if !result
            .ehlo_capabilities
            .iter()
            .any(|c| c.eq_ignore_ascii_case("STARTTLS"))
        {
            result.starttls = ProbeStartTlsResult::NotAdvertised;
            reader.get_mut().write_all(b"QUIT\r\n").await?;
            return Ok(());
        }
        reader.get_mut().write_all(b"STARTTLS\r\n").await?;
        let reply = read_multiline_response(&mut reader, limits).await?;
        if !reply[0].starts_with("220") {
            result.starttls = ProbeStartTlsResult::AdvertisedAndRejected;
            result.error = Some(format!("STARTTLS rejected: {}", reply.join(" ")));
            reader.get_mut().write_all(b"QUIT\r\n").await?;
            return Ok(());
        }
        result.starttls = ProbeStartTlsResult::AcceptedHandshakeFailed;
    } else {
        result.starttls = ProbeStartTlsResult::ImplicitTls;
    }
    if !reader.buffer().is_empty() {
        return Err(SmtpProbeError::Protocol(
            "unexpected plaintext after STARTTLS acceptance".into(),
        ));
    }
    let tls_error =
        |e: openssl::error::ErrorStack| SmtpProbeError::TlsHandshakeFailed(e.to_string());
    let mut connector = SslConnector::builder(SslMethod::tls()).map_err(tls_error)?;
    if let Some(version) = &limits.forced_tls_version {
        let version = match version {
            TlsVersion::Tls10 => openssl::ssl::SslVersion::TLS1,
            TlsVersion::Tls11 => openssl::ssl::SslVersion::TLS1_1,
            TlsVersion::Tls12 => openssl::ssl::SslVersion::TLS1_2,
            TlsVersion::Tls13 => openssl::ssl::SslVersion::TLS1_3,
            TlsVersion::Unknown(_) => {
                return Err(SmtpProbeError::Protocol(
                    "unknown TLS challenge version".into(),
                ));
            }
        };
        connector
            .set_min_proto_version(Some(version))
            .map_err(tls_error)?;
        connector
            .set_max_proto_version(Some(version))
            .map_err(tls_error)?;
        connector.set_security_level(0);
        connector
            .set_cipher_list("ALL:@SECLEVEL=0")
            .map_err(tls_error)?;
    }
    // Observe invalid chains too, while retaining OpenSSL's verification result.
    connector.set_verify_callback(SslVerifyMode::PEER, |_, _| true);
    let ssl = connector
        .build()
        .configure()
        .map_err(tls_error)?
        .into_ssl(host)
        .map_err(tls_error)?;
    let mut tls = tokio_openssl::SslStream::new(ssl, reader.into_inner()).map_err(tls_error)?;
    if let Err(e) = Pin::new(&mut tls).connect().await {
        result.error = Some(format!("TLS handshake failed: {e}"));
        return Ok(());
    }
    if ehlo.is_some() {
        result.starttls = ProbeStartTlsResult::AdvertisedAndAccepted;
    }
    let ssl = tls.ssl();
    result.tls_version = Some(match ssl.version_str() {
        "TLSv1" => TlsVersion::Tls10,
        "TLSv1.1" => TlsVersion::Tls11,
        "TLSv1.2" => TlsVersion::Tls12,
        "TLSv1.3" => TlsVersion::Tls13,
        other => TlsVersion::Unknown(other.into()),
    });
    result.cipher_suite = ssl.current_cipher().map(|c| CipherSuite {
        id: Some(u16::from_be_bytes(c.protocol_id())),
        name: c.standard_name().unwrap_or(c.name()).into(),
    });
    result.forward_secrecy = if ssl.peer_tmp_key().is_ok() {
        ForwardSecrecyState::Supported
    } else if result
        .cipher_suite
        .as_ref()
        .is_some_and(|c| c.name.starts_with("TLS_RSA_WITH_"))
    {
        ForwardSecrecyState::NotSupported
    } else {
        ForwardSecrecyState::Unknown
    };
    let verify_ok = ssl.verify_result() == openssl::x509::X509VerifyResult::OK;
    result.certificate_trusted = Some(verify_ok);
    if let Some(cert) = ssl.peer_certificate() {
        let der = cert.to_der().map_err(tls_error)?;
        result.spki_der = cert
            .public_key()
            .and_then(|k| k.public_key_to_der())
            .map_err(tls_error)?;
        let (mut observation, hostname_valid) = parse_certificate(&der, host)?;
        // Chain/trust state is deterministic active-probe evidence from OpenSSL.
        let details = observation
            .crypto_details
            .as_mut()
            .expect("parsed certificate has crypto details");
        details.chain_validation = if verify_ok {
            mailent_domain::ChainValidation::Verified
        } else {
            mailent_domain::ChainValidation::Failed
        };
        details.public_key.spki_sha256 = {
            use sha2::{Digest, Sha256};
            Some(
                Sha256::digest(&result.spki_der)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
            )
        };
        result.certificate = Some(observation);
        result.certificate_hostname_valid = Some(hostname_valid);
        result.certificate_der = der;
    }
    // No application commands on implicit TLS: IMAP/POP3 have different logout syntax.
    if ehlo.is_some() {
        tls.write_all(b"QUIT\r\n").await?;
    }
    Ok(())
}

fn require_code(lines: &[String], code: &str) -> Result<(), SmtpProbeError> {
    if lines.first().is_some_and(|l| l.starts_with(code)) {
        Ok(())
    } else {
        Err(SmtpProbeError::Protocol(format!(
            "expected {code}, received {}",
            lines.join(" ")
        )))
    }
}

async fn read_multiline_response<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    limits: &ProbeLimits,
) -> Result<Vec<String>, SmtpProbeError> {
    let mut lines = Vec::new();
    let mut code = None;
    for _ in 0..limits.max_exchange_lines {
        let mut bytes = Vec::new();
        reader
            .take(limits.max_line_bytes as u64 + 1)
            .read_until(b'\n', &mut bytes)
            .await?;
        if bytes.len() > limits.max_line_bytes || !bytes.ends_with(b"\r\n") || bytes.len() < 6 {
            return Err(SmtpProbeError::Protocol(
                "truncated, oversized, or malformed SMTP response".into(),
            ));
        }
        let line = String::from_utf8(bytes)
            .map_err(|_| SmtpProbeError::Protocol("non-UTF8 SMTP response".into()))?;
        let prefix = &line.as_bytes()[..3];
        if !prefix.iter().all(u8::is_ascii_digit)
            || !matches!(line.as_bytes()[3], b' ' | b'-')
            || code.as_ref().is_some_and(|c: &Vec<u8>| c != prefix)
        {
            return Err(SmtpProbeError::Protocol(
                "invalid SMTP reply code or continuation".into(),
            ));
        }
        code = Some(prefix.to_vec());
        let last = line.as_bytes()[3] == b' ';
        lines.push(line.trim_end().into());
        if last {
            return Ok(lines);
        }
    }
    Err(SmtpProbeError::Protocol(
        "SMTP response exceeded line limit".into(),
    ))
}

fn parse_certificate(
    der: &[u8],
    host: &str,
) -> Result<(CertificateObservation, bool), SmtpProbeError> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| SmtpProbeError::Protocol(format!("invalid certificate: {e}")))?;
    let mut sans = Vec::new();
    let mut valid = false;
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            match name {
                GeneralName::DNSName(dns) => {
                    sans.push(dns.to_string());
                    if host.parse::<std::net::IpAddr>().is_err() {
                        valid |= hostname_matches(dns, host);
                    }
                }
                GeneralName::IPAddress(bytes) => {
                    let ip = match bytes.len() {
                        4 => Some(std::net::IpAddr::from(
                            <[u8; 4]>::try_from(*bytes).expect("length checked"),
                        )),
                        16 => Some(std::net::IpAddr::from(
                            <[u8; 16]>::try_from(*bytes).expect("length checked"),
                        )),
                        _ => None,
                    };
                    if let Some(ip) = ip {
                        valid |= host.parse::<std::net::IpAddr>().ok() == Some(ip);
                        sans.push(ip.to_string());
                    }
                }
                _ => {}
            }
        }
    }
    let openssl_cert =
        openssl::x509::X509::from_der(der).map_err(|e| SmtpProbeError::Protocol(e.to_string()))?;
    let self_signed = cert.subject() == cert.issuer()
        && openssl_cert
            .public_key()
            .and_then(|k| openssl_cert.verify(&k))
            .unwrap_or(false);
    Ok((
        CertificateObservation {
            reference: CertificateReference {
                sha256_fingerprint: Sha256::digest(der)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
                subject: cert.subject().to_string(),
                issuer: cert.issuer().to_string(),
            },
            validity: ValidityPeriod {
                not_before: cert.validity().not_before.to_datetime(),
                not_after: cert.validity().not_after.to_datetime(),
            },
            is_self_signed: Some(self_signed),
            san: sans,
            // Extract crypto details (PK algorithm/size, signature algorithm,
            // extensions) from the same DER the probe already parsed.
            crypto_details: Some(crate::certificate::crypto_details(&cert)),
        },
        valid,
    ))
}
fn hostname_matches(pattern: &str, host: &str) -> bool {
    let p = pattern.to_ascii_lowercase();
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    p == h
        || p.strip_prefix("*.")
            .is_some_and(|suffix| h.split_once('.').is_some_and(|(_, rest)| rest == suffix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthorizedDomain, ProbeScope};
    use tokio::net::TcpListener;
    fn scope() -> ProbeScope {
        ProbeScope::new(vec![AuthorizedDomain {
            domain: "127.0.0.1/32".into(),
            authorization_ref: "test".into(),
        }])
    }

    #[tokio::test]
    async fn authorization_precedes_any_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let result = probe_smtp_starttls(
            "127.0.0.1",
            listener.local_addr().unwrap().port(),
            "mailent-test",
            &ProbeLimits::default(),
            &ProbeScope::new(vec![]),
        )
        .await;
        assert!(matches!(result, Err(SmtpProbeError::ScopeRejected(_))));
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn smtp_caps_preserved_and_no_mail_commands() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"220 test ready\r\n").await.unwrap();
            let mut reader = BufReader::new(stream);
            let mut command = String::new();
            reader.read_line(&mut command).await.unwrap();
            assert_eq!(command, "EHLO mailent-test\r\n");
            reader
                .get_mut()
                .write_all(b"250-test\r\n250 8BITMIME\r\n")
                .await
                .unwrap();
            command.clear();
            reader.read_line(&mut command).await.unwrap();
            assert_eq!(command, "QUIT\r\n");
        });
        let result = probe_smtp_starttls(
            "127.0.0.1",
            port,
            "mailent-test",
            &ProbeLimits::default(),
            &scope(),
        )
        .await
        .unwrap();
        assert_eq!(result.starttls, ProbeStartTlsResult::NotAdvertised);
        assert!(result.ehlo_capabilities.contains(&"8BITMIME".into()));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn bounded_malformed_response_and_deadline() {
        for response in [
            b"".as_slice(),
            b"220 test\n",
            b"220-more\r\n250 invalid\r\n",
            &[b'x'; 2048],
        ] {
            let mut reader = BufReader::new(response);
            assert!(
                read_multiline_response(&mut reader, &ProbeLimits::default())
                    .await
                    .is_err()
            );
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        let limits = ProbeLimits {
            read_timeout: Duration::from_millis(30),
            ..Default::default()
        };
        assert!(matches!(
            probe_smtp_starttls("127.0.0.1", port, "mailent-test", &limits, &scope())
                .await
                .unwrap_err()
                .root(),
            SmtpProbeError::Timeout(_)
        ));
        server.abort();
        let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = unused.local_addr().unwrap().port();
        drop(unused);
        assert!(matches!(
            probe_implicit_tls("127.0.0.1", port, &limits, &scope())
                .await
                .unwrap_err()
                .root(),
            SmtpProbeError::ConnectionRefused
        ));
    }

    #[test]
    fn identity_matching_is_single_label_and_ip_scope_is_explicit() {
        assert!(hostname_matches("*.example.com", "mx.example.com"));
        assert!(!hostname_matches("*.example.com", "deep.mx.example.com"));
        assert!(scope().is_authorized("127.0.0.1"));
        assert!(!scope().is_authorized("127.0.0.2"));
        assert!(!scope().is_authorized("127.0.0.1\r\nMAIL FROM:"));
    }

    #[tokio::test]
    #[ignore = "requires fixtures/lab/generate.py --serve mapped to local lab ports"]
    async fn real_postfix_dovecot_transport() {
        let result = probe_smtp_starttls(
            "127.0.0.1",
            12525,
            "mailent-test",
            &ProbeLimits::default(),
            &scope(),
        )
        .await
        .unwrap();
        assert_eq!(result.starttls, ProbeStartTlsResult::AdvertisedAndAccepted);
        assert!(result.tls_version.is_some());
        assert!(result.cipher_suite.is_some());
        assert_eq!(result.forward_secrecy, ForwardSecrecyState::Supported);
        let cert = result.certificate.unwrap();
        assert!(cert.validity.is_expired_at(time::OffsetDateTime::now_utc()));
        assert_eq!(result.certificate_trusted, Some(false));
        for port in [12993, 12995] {
            let r = probe_implicit_tls("127.0.0.1", port, &ProbeLimits::default(), &scope())
                .await
                .unwrap();
            assert_eq!(r.starttls, ProbeStartTlsResult::ImplicitTls);
            assert!(r.tls_version.is_some());
            assert!(r.certificate.is_some());
        }
    }
}
