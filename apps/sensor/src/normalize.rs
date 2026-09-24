//! Zeek JSON adapter. Protocol reconstruction and certificate parsing belong to Zeek.
use crate::SensorError;
use mailent_domain::*;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};
use time::OffsetDateTime;
use uuid::Uuid;

pub const NORMALIZER_VERSION: &str = "mailent-zeek/1";
const LOGS: &[&str] = &[
    "conn.log",
    "smtp.log",
    "ssl.log",
    "tls.log",
    "x509.log",
    "files.log",
    "mailent.log",
];

#[derive(Debug, Clone)]
struct Record {
    value: Value,
    source: String,
}
impl Record {
    fn text(&self, key: &str) -> Result<Option<&str>, SensorError> {
        match self.value.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s)),
            _ => Err(self.bad(key)),
        }
    }
    fn required(&self, key: &str) -> Result<&str, SensorError> {
        self.text(key)?.ok_or_else(|| self.bad(key))
    }
    fn number(&self, key: &str) -> Result<Option<f64>, SensorError> {
        match self.value.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Number(n)) => n
                .as_f64()
                .filter(|n| n.is_finite())
                .map(Some)
                .ok_or_else(|| self.bad(key)),
            _ => Err(self.bad(key)),
        }
    }
    fn boolean(&self, key: &str) -> Result<Option<bool>, SensorError> {
        match self.value.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Bool(b)) => Ok(Some(*b)),
            _ => Err(self.bad(key)),
        }
    }
    fn strings(&self, key: &str) -> Result<Vec<&str>, SensorError> {
        match self.value.get(key) {
            None | Some(Value::Null) => Ok(vec![]),
            Some(Value::Array(values)) => values
                .iter()
                .map(|v| v.as_str().ok_or_else(|| self.bad(key)))
                .collect(),
            _ => Err(self.bad(key)),
        }
    }
    fn time(&self, key: &str) -> Result<OffsetDateTime, SensorError> {
        let n = self.number(key)?.ok_or_else(|| self.bad(key))?;
        if !(-62167219200.0..=253402300799.0).contains(&n) {
            return Err(self.bad(key));
        }
        OffsetDateTime::from_unix_timestamp_nanos((n * 1_000_000_000.0).round() as i128)
            .map_err(|_| self.bad(key))
    }
    fn bad(&self, key: &str) -> SensorError {
        SensorError::Normalize(format!("{}: missing or invalid field {key}", self.source))
    }
    fn port(&self, key: &str) -> Result<u16, SensorError> {
        self.value
            .get(key)
            .and_then(Value::as_u64)
            .and_then(|v| u16::try_from(v).ok())
            .filter(|v| *v > 0)
            .ok_or_else(|| self.bad(key))
    }
    fn flow(&self) -> Result<NetworkFlow, SensorError> {
        Ok(NetworkFlow {
            src_ip: self.required("id.orig_h")?.into(),
            src_port: self.port("id.orig_p")?,
            dst_ip: self.required("id.resp_h")?.into(),
            dst_port: self.port("id.resp_p")?,
        })
    }
}

fn read_logs(dir: &Path) -> Result<BTreeMap<String, Vec<Record>>, SensorError> {
    let mut logs = BTreeMap::new();
    for name in LOGS {
        let path = dir.join(name);
        if !path.exists() {
            continue;
        }
        if path.metadata()?.len() > 64 * 1024 * 1024 {
            return Err(SensorError::Normalize(format!(
                "{name} exceeds the 64 MiB local import limit"
            )));
        }
        let reader = BufReader::new(File::open(path)?);
        let mut records = Vec::new();
        for (line_index, line) in reader.lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let source = format!("{name}:{}", line_index + 1);
            if line.len() > 1024 * 1024 {
                return Err(SensorError::Normalize(format!(
                    "{source}: record exceeds 1 MiB"
                )));
            }
            let value: Value = serde_json::from_str(&line).map_err(|e| {
                SensorError::Normalize(format!("{source}: malformed Zeek JSON: {e}"))
            })?;
            if !value.is_object() {
                return Err(SensorError::Normalize(format!(
                    "{source}: expected a JSON object"
                )));
            }
            records.push(Record { value, source });
        }
        logs.insert((*name).into(), records);
    }
    Ok(logs)
}

/// Normalize one isolated Zeek run. Never combine UIDs from unrelated captures.
pub fn normalize(
    dir: &Path,
    capture_sha256: &str,
    sensor_id: &str,
    zeek_version: &str,
) -> Result<Vec<NormalizedObservation>, SensorError> {
    let logs = read_logs(dir)?;
    let mut connections: BTreeMap<String, Vec<&Record>> = BTreeMap::new();
    let mut certificates: BTreeMap<String, &Record> = BTreeMap::new();
    let mut file_hashes: BTreeMap<String, &str> = BTreeMap::new();
    for (name, records) in &logs {
        for record in records {
            match name.as_str() {
                "x509.log" => {
                    let key = record
                        .text("fingerprint")?
                        .or(record.text("id")?)
                        .ok_or_else(|| record.bad("fingerprint or id"))?;
                    if let Some(previous) = certificates.insert(key.into(), record) {
                        // Zeek can re-log the same certificate. Distinct content under a single key is ambiguous.
                        for field in [
                            "certificate.subject",
                            "certificate.issuer",
                            "certificate.not_valid_before",
                            "certificate.not_valid_after",
                        ] {
                            if previous.value.get(field) != record.value.get(field) {
                                return Err(record.bad("conflicting certificate identity"));
                            }
                        }
                    }
                }
                "files.log" => {
                    if let (Some(id), Some(hash)) = (record.text("fuid")?, record.text("sha256")?) {
                        file_hashes.insert(id.into(), hash);
                    }
                }
                _ => {
                    connections
                        .entry(record.required("uid")?.into())
                        .or_default()
                        .push(record);
                }
            }
        }
    }
    if connections.len() > 100_000 {
        return Err(SensorError::Normalize(
            "capture exceeds 100,000 connections".into(),
        ));
    }
    let mut observations = Vec::new();
    for (uid, records) in connections {
        let conn = records
            .iter()
            .find(|r| r.source.starts_with("conn.log:"))
            .copied();
        let ssl_records: Vec<_> = records
            .iter()
            .copied()
            .filter(|r| r.source.starts_with("ssl.log:") || r.source.starts_with("tls.log:"))
            .collect();
        let ssl = ssl_records.first().copied();
        let smtp = records
            .iter()
            .find(|r| r.source.starts_with("smtp.log:"))
            .copied();
        let events: Vec<_> = records
            .iter()
            .copied()
            .filter(|r| r.source.starts_with("mailent.log:"))
            .collect();
        let mut protocols = BTreeSet::new();
        if smtp.is_some() {
            protocols.insert("smtp");
        }
        for event in &events {
            let protocol = event.required("protocol")?;
            if !protocol.is_empty() {
                protocols.insert(protocol);
            }
        }
        if let Some(c) = conn {
            if c.text("proto")?.is_some_and(|p| p != "tcp") {
                continue;
            }
            if let Some(service) = c.text("service")? {
                for name in service.split(',') {
                    if ["smtp", "imap", "pop3"].contains(&name) {
                        protocols.insert(name);
                    }
                }
            }
        }
        let flow_record = conn.or(smtp).or(ssl);
        let hint = flow_record
            .map(|r| r.port("id.resp_p"))
            .transpose()?
            .and_then(|port| match port {
                465 => Some(EmailProtocol::Smtp),
                993 => Some(EmailProtocol::Imap),
                995 => Some(EmailProtocol::Pop3),
                _ => None,
            });
        if protocols.is_empty() && !(ssl.is_some() && hint.is_some()) {
            continue;
        }
        let base = flow_record.ok_or_else(|| {
            SensorError::Normalize(format!(
                "connection {uid}: email evidence has no flow record"
            ))
        })?;
        let mut gaps = Vec::new();
        let protocol = if protocols.len() == 1 {
            match *protocols.first().unwrap_or(&"") {
                "smtp" => EmailProtocol::Smtp,
                "imap" => EmailProtocol::Imap,
                "pop3" => EmailProtocol::Pop3,
                _ => EmailProtocol::Unknown,
            }
        } else {
            EmailProtocol::Unknown
        };
        if protocol == EmailProtocol::Unknown {
            gaps.push("Application protocol unavailable or conflicting; any port hint is not observed protocol evidence".into());
        }
        if conn.is_none() {
            gaps.push("Connection log unavailable".into());
        }
        let history = conn
            .map(|r| r.text("history"))
            .transpose()?
            .flatten()
            .unwrap_or("");
        if !history.contains('S') || !history.contains('h') {
            gaps.push("TCP opening handshake incomplete; capture may begin mid-stream".into());
        }
        if conn
            .map(|r| r.number("missed_bytes"))
            .transpose()?
            .flatten()
            .unwrap_or(0.0)
            > 0.0
        {
            gaps.push("Zeek reported missing TCP bytes".into());
        }
        let closed = conn
            .map(|r| r.text("conn_state"))
            .transpose()?
            .flatten()
            .is_some_and(|s| matches!(s, "SF" | "RSTO" | "RSTR"));
        if !closed {
            gaps.push("Connection end unavailable; capture may be truncated".into());
        }
        let mut timeline = Vec::new();
        let mut cipher_id = None;
        let mut kx = None;
        for event in &events {
            let kind = event.required("kind")?;
            if kind == "tls_server_hello" {
                cipher_id = event
                    .value
                    .get("cipher_id")
                    .and_then(Value::as_u64)
                    .map(|n| u16::try_from(n).map_err(|_| event.bad("cipher_id")))
                    .transpose()?;
            }
            kx = match kind {
                "key_exchange_ecdhe" => Some(KeyExchange::Ecdhe),
                "key_exchange_dhe" => Some(KeyExchange::Dhe),
                "key_exchange_rsa_static" => Some(KeyExchange::RsaStatic),
                _ => kx,
            };
            timeline.push(TimelineEvent {
                timestamp: event.time("ts")?,
                kind: kind.into(),
                source: event.source.clone(),
            });
        }
        timeline.sort_by_key(|e| e.timestamp); // Stable ordering preserves same-packet event order.
        let has = |kind: &str| timeline.iter().any(|e| e.kind == kind);
        let established = ssl
            .map(|r| r.boolean("established"))
            .transpose()?
            .flatten()
            .or_else(|| has("tls_established").then_some(true));
        let upgraded = has("starttls_accepted")
            || smtp.map(|r| r.boolean("tls")).transpose()?.flatten() == Some(true);
        let starttls_state =
            reconstruct_starttls(&timeline, upgraded, established, closed && gaps.is_empty());
        let tls_version = ssl
            .map(|r| r.text("version"))
            .transpose()?
            .flatten()
            .map(|v| match v {
                "TLSv10" | "TLSv1.0" => TlsVersion::Tls10,
                "TLSv11" | "TLSv1.1" => TlsVersion::Tls11,
                "TLSv12" | "TLSv1.2" => TlsVersion::Tls12,
                "TLSv13" | "TLSv1.3" => TlsVersion::Tls13,
                _ => TlsVersion::Unknown(v.into()),
            });
        let cipher_suite = ssl
            .map(|r| r.text("cipher"))
            .transpose()?
            .flatten()
            .map(|name| CipherSuite {
                id: cipher_id,
                name: name.into(),
            });
        if kx.is_none() && !matches!(tls_version, Some(TlsVersion::Tls13)) {
            // Cipher vocabulary supplied by Zeek; TLS 1.3 ciphers do not specify key exchange.
            if let Some(cipher) = &cipher_suite {
                kx = if cipher.name.starts_with("TLS_ECDHE_") {
                    Some(KeyExchange::Ecdhe)
                } else if cipher.name.starts_with("TLS_DHE_") {
                    Some(KeyExchange::Dhe)
                } else if cipher.name.starts_with("TLS_RSA_WITH_") {
                    Some(KeyExchange::RsaStatic)
                } else {
                    None
                };
            }
        }
        let mut sources: Vec<String> = records.iter().map(|r| r.source.clone()).collect();
        let mut certificate = None;
        if let Some(tls) = ssl {
            let fps = tls.strings("cert_chain_fps")?;
            let fuids = tls.strings("cert_chain_fuids")?;
            let cert_lookup = fps
                .first()
                .or(fuids.first())
                .and_then(|key| certificates.get(*key).map(|cert| (*key, cert)));
            if let Some((key, cert)) = cert_lookup {
                let fingerprint = cert
                    .text("fingerprint")?
                    .or_else(|| file_hashes.get(key).copied());
                if let Some(fingerprint) = fingerprint {
                    let subject = cert.required("certificate.subject")?.to_string();
                    let issuer = cert.required("certificate.issuer")?.to_string();
                    let is_self_signed = Some(subject == issuer);

                    // Extract X.509 PKI crypto details from Zeek's x509.log
                    let sig_alg = cert.text("certificate.sig_alg")?.map(str::to_string);
                    let key_type = cert.text("certificate.key_type")?;
                    let key_alg = cert.text("certificate.key_alg")?;
                    let key_length = cert.number("certificate.key_length")?.map(|n| n as u16);

                    let is_rsa = key_type.is_some_and(|t| t.eq_ignore_ascii_case("rsa"))
                        || key_alg.is_some_and(|a| a.to_ascii_lowercase().contains("rsa"));
                    let is_ec = key_type.is_some_and(|t| t.eq_ignore_ascii_case("ecdsa") || t.eq_ignore_ascii_case("ec"))
                        || key_alg.is_some_and(|a| a.to_ascii_lowercase().contains("ec"));
                    let is_ed25519 = key_type.is_some_and(|t| t.eq_ignore_ascii_case("ed25519"))
                        || key_alg.is_some_and(|a| a.to_ascii_lowercase().contains("25519"));

                    let (pub_alg, rsa_bits, ec_curve) = if is_rsa {
                        (Some("RSA".to_string()), key_length, None)
                    } else if is_ec {
                        let curve = cert.text("certificate.curve")?.map(str::to_string);
                        (Some("EC".to_string()), None, curve)
                    } else if is_ed25519 {
                        (Some("Ed25519".to_string()), None, None)
                    } else {
                        (
                            key_type.or(key_alg).map(|s| s.to_ascii_uppercase()),
                            None,
                            None,
                        )
                    };

                    let basic_constraints = cert.boolean("basic_constraints.ca")?.map(|is_ca| {
                        if is_ca {
                            "CA:TRUE".to_string()
                        } else {
                            "CA:FALSE".to_string()
                        }
                    });

                    let chain_len = if !fps.is_empty() {
                        Some(fps.len() as u8)
                    } else if !fuids.is_empty() {
                        Some(fuids.len() as u8)
                    } else {
                        None
                    };

                    let crypto_details = Some(CertificateCryptoDetails {
                        signature_algorithm: sig_alg,
                        public_key: PublicKeyDetails {
                            algorithm: pub_alg,
                            rsa_bits,
                            ec_curve,
                            spki_sha256: None,
                        },
                        chain_validation: ChainValidation::NotVerified,
                        chain_length: chain_len,
                        extensions: CertificateExtensions {
                            basic_constraints,
                            key_usage: Vec::new(),
                            extended_key_usage: Vec::new(),
                        },
                    });

                    certificate = Some(CertificateObservation {
                        reference: CertificateReference {
                            sha256_fingerprint: fingerprint.into(),
                            subject,
                            issuer,
                        },
                        validity: ValidityPeriod {
                            not_before: cert.time("certificate.not_valid_before")?,
                            not_after: cert.time("certificate.not_valid_after")?,
                        },
                        is_self_signed,
                        san: cert
                            .strings("san.dns")?
                            .iter()
                            .map(|s| (*s).into())
                            .collect(),
                        crypto_details,
                    });
                    sources.push(cert.source.clone());
                } else {
                    gaps.push("Certificate SHA-256 unavailable in imported logs".into());
                }
            }
        }
        if ssl_records.len() > 1 {
            return Err(SensorError::Normalize(format!(
                "connection {uid}: multiple TLS records/renegotiations are not yet supported; refusing to choose a handshake"
            )));
        }
        if tls_version.is_none() {
            gaps.push("TLS negotiation unavailable".into());
        }
        if certificate.is_none() {
            gaps.push(
                "Server certificate unavailable (not visible, encrypted, resumed, or missing log)"
                    .into(),
            );
        }
        if events.is_empty() {
            gaps.push("Mailent event log unavailable; detailed STARTTLS timeline unknown".into());
        }
        sources.sort();
        sources.dedup();
        let timestamp = ssl.unwrap_or(base).time("ts")?;
        // Zeek UIDs vary across runs. Flow + capture start uniquely identify a connection within this capture.
        let flow = base.flow()?;
        let identity = serde_json::to_vec(&(
            capture_sha256,
            sensor_id,
            base.time("ts")?.unix_timestamp_nanos(),
            &flow,
        ))?;
        let observation = NormalizedObservation {
            observation_id: Uuid::new_v5(&Uuid::NAMESPACE_OID, &identity),
            timestamp,
            sensor_id: sensor_id.into(),
            provenance: ObservationProvenance {
                source: "pcap".into(),
                parser: "zeek".into(),
                parser_version: zeek_version.into(),
            },
            flow,
            protocol,
            starttls_state,
            tls_version,
            cipher_suite,
            key_exchange: kx,
            certificate,
            capture: Some(CaptureEvidence {
                capture_sha256: capture_sha256.into(),
                connection_uid: uid,
                normalizer_version: NORMALIZER_VERSION.into(),
                source_logs: sources,
                timeline,
                gaps,
                tls_established: established,
                protocol_hint: hint,
            }),
            raw_metadata: None,
        };
        observation
            .validate()
            .map_err(|e| SensorError::Normalize(e.to_string()))?;
        observations.push(observation);
    }
    observations.sort_by_key(|o| (o.timestamp, o.observation_id));
    Ok(observations)
}

pub fn reconstruct_starttls(
    timeline: &[TimelineEvent],
    upgraded: bool,
    established: Option<bool>,
    complete: bool,
) -> Option<StartTlsState> {
    let has = |kind: &str| timeline.iter().any(|e| e.kind == kind);
    if has("plaintext_continuation") {
        return Some(StartTlsState::PlaintextContinuation);
    }
    if has("tls_fatal_alert") && (upgraded || has("starttls_requested")) {
        return Some(StartTlsState::FailedHandshake);
    }
    if upgraded && established == Some(true) {
        return Some(StartTlsState::TlsEstablished);
    }
    if has("starttls_rejected") {
        return Some(StartTlsState::Rejected);
    }
    if upgraded && has("tls_client_hello") {
        return Some(StartTlsState::TlsStarted);
    }
    if upgraded {
        return Some(StartTlsState::Accepted);
    }
    if has("starttls_requested") {
        return Some(StartTlsState::Requested);
    }
    if has("starttls_advertised") {
        return Some(if complete {
            StartTlsState::AdvertisedNotUsed
        } else {
            StartTlsState::Advertised
        });
    }
    if has("starttls_not_advertised") {
        return Some(StartTlsState::NotAdvertised);
    }
    None
}
