//! Generated Protobuf stays at the event boundary, outside `domain`.
use mailent_domain as d;
use prost::Message;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/mailent.observation.v1.rs"));
}

fn invalid(message: impl Into<String>) -> d::DomainError {
    d::DomainError::InvalidObservation(message.into())
}
fn required<T>(value: Option<T>, name: &str) -> Result<T, d::DomainError> {
    value.ok_or_else(|| invalid(format!("missing {name}")))
}
fn date(value: &str) -> Result<OffsetDateTime, d::DomainError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|e| invalid(e.to_string()))
}
fn format_date(value: OffsetDateTime) -> Result<String, d::DomainError> {
    value.format(&Rfc3339).map_err(|e| invalid(e.to_string()))
}

pub fn encode(observation: &d::NormalizedObservation) -> Result<Vec<u8>, d::DomainError> {
    observation.validate()?;
    if observation.raw_metadata.is_some() {
        return Err(invalid(
            "raw metadata must be minimized before event transport",
        ));
    }
    let o = observation;
    let certificate = o
        .certificate
        .as_ref()
        .map(|c| {
            Ok::<_, d::DomainError>(v1::Certificate {
                sha256_fingerprint: c.reference.sha256_fingerprint.clone(),
                subject: c.reference.subject.clone(),
                issuer: c.reference.issuer.clone(),
                not_before: format_date(c.validity.not_before)?,
                not_after: format_date(c.validity.not_after)?,
                is_self_signed: c.is_self_signed,
                san: c.san.clone(),
            })
        })
        .transpose()?;
    let key_exchange = o.key_exchange.as_ref().map(|k| {
        let (kind, name) = match k {
            d::KeyExchange::Ecdhe => ("ecdhe", ""),
            d::KeyExchange::Dhe => ("dhe", ""),
            d::KeyExchange::RsaStatic => ("rsa_static", ""),
            d::KeyExchange::HybridPqc(n) => ("hybrid_pqc", n.as_str()),
            d::KeyExchange::Unknown(n) => ("unknown", n.as_str()),
        };
        v1::KeyExchange {
            kind: kind.into(),
            name: name.into(),
        }
    });
    Ok(v1::ObservationEnvelope {
        schema_version: 1,
        observation: Some(v1::Observation {
            observation_id: o.observation_id.to_string(),
            timestamp: format_date(o.timestamp)?,
            sensor_id: o.sensor_id.clone(),
            provenance: Some(v1::Provenance {
                source: o.provenance.source.clone(),
                parser: o.provenance.parser.clone(),
                parser_version: o.provenance.parser_version.clone(),
            }),
            flow: Some(v1::NetworkFlow {
                src_ip: o.flow.src_ip.clone(),
                src_port: o.flow.src_port.into(),
                dst_ip: o.flow.dst_ip.clone(),
                dst_port: o.flow.dst_port.into(),
            }),
            protocol: match o.protocol {
                d::EmailProtocol::Smtp => 1,
                d::EmailProtocol::Imap => 2,
                d::EmailProtocol::Pop3 => 3,
                d::EmailProtocol::Unknown => 4,
            },
            starttls_state: o.starttls_state.map(|s| match s {
                d::StartTlsState::AdvertisedAndUsed => 1,
                d::StartTlsState::AdvertisedNotUsed => 2,
                d::StartTlsState::NotAdvertised => 3,
                d::StartTlsState::Rejected => 4,
                d::StartTlsState::FailedHandshake => 5,
                d::StartTlsState::PlaintextContinuation => 6,
                d::StartTlsState::Advertised => 7,
                d::StartTlsState::Requested => 8,
                d::StartTlsState::Accepted => 9,
                d::StartTlsState::TlsStarted => 10,
                d::StartTlsState::TlsEstablished => 11,
            }),
            tls_version: o.tls_version.as_ref().map(ToString::to_string),
            cipher_suite: o.cipher_suite.as_ref().map(|c| v1::CipherSuite {
                id: c.id.map(Into::into),
                name: c.name.clone(),
            }),
            key_exchange,
            certificate,
            capture: o.capture.as_ref().map(encode_capture).transpose()?,
        }),
    }
    .encode_to_vec())
}

pub fn decode(bytes: &[u8]) -> Result<d::NormalizedObservation, d::DomainError> {
    let envelope = v1::ObservationEnvelope::decode(bytes).map_err(|e| invalid(e.to_string()))?;
    if envelope.schema_version != 1 {
        return Err(invalid("unsupported observation schema version"));
    }
    let o = required(envelope.observation, "observation")?;
    let p = required(o.provenance, "provenance")?;
    let f = required(o.flow, "flow")?;
    let observation = d::NormalizedObservation {
        observation_id: Uuid::parse_str(&o.observation_id).map_err(|e| invalid(e.to_string()))?,
        timestamp: date(&o.timestamp)?,
        sensor_id: o.sensor_id,
        provenance: d::ObservationProvenance {
            source: p.source,
            parser: p.parser,
            parser_version: p.parser_version,
        },
        flow: d::NetworkFlow {
            src_ip: f.src_ip,
            src_port: f
                .src_port
                .try_into()
                .map_err(|_| invalid("src_port out of range"))?,
            dst_ip: f.dst_ip,
            dst_port: f
                .dst_port
                .try_into()
                .map_err(|_| invalid("dst_port out of range"))?,
        },
        protocol: match o.protocol {
            1 => d::EmailProtocol::Smtp,
            2 => d::EmailProtocol::Imap,
            3 => d::EmailProtocol::Pop3,
            4 => d::EmailProtocol::Unknown,
            _ => return Err(invalid("unknown mail protocol")),
        },
        starttls_state: o
            .starttls_state
            .map(|s| {
                Ok(match s {
                    1 => d::StartTlsState::AdvertisedAndUsed,
                    2 => d::StartTlsState::AdvertisedNotUsed,
                    3 => d::StartTlsState::NotAdvertised,
                    4 => d::StartTlsState::Rejected,
                    5 => d::StartTlsState::FailedHandshake,
                    6 => d::StartTlsState::PlaintextContinuation,
                    7 => d::StartTlsState::Advertised,
                    8 => d::StartTlsState::Requested,
                    9 => d::StartTlsState::Accepted,
                    10 => d::StartTlsState::TlsStarted,
                    11 => d::StartTlsState::TlsEstablished,
                    _ => return Err(invalid("unknown STARTTLS state")),
                })
            })
            .transpose()?,
        tls_version: o.tls_version.map(|v| match v.as_str() {
            "TLSv1.0" => d::TlsVersion::Tls10,
            "TLSv1.1" => d::TlsVersion::Tls11,
            "TLSv1.2" => d::TlsVersion::Tls12,
            "TLSv1.3" => d::TlsVersion::Tls13,
            _ => d::TlsVersion::Unknown(v),
        }),
        cipher_suite: o
            .cipher_suite
            .map(|c| {
                Ok::<_, d::DomainError>(d::CipherSuite {
                    id: c
                        .id
                        .map(u16::try_from)
                        .transpose()
                        .map_err(|_| invalid("cipher id out of range"))?,
                    name: c.name,
                })
            })
            .transpose()?,
        key_exchange: o.key_exchange.map(|k| match k.kind.as_str() {
            "ecdhe" => d::KeyExchange::Ecdhe,
            "dhe" => d::KeyExchange::Dhe,
            "rsa_static" => d::KeyExchange::RsaStatic,
            "hybrid_pqc" => d::KeyExchange::HybridPqc(k.name),
            "unknown" => d::KeyExchange::Unknown(k.name),
            _ => d::KeyExchange::Unknown(k.kind),
        }),
        certificate: o
            .certificate
            .map(|c| {
                Ok::<_, d::DomainError>(d::CertificateObservation {
                    reference: d::CertificateReference {
                        sha256_fingerprint: c.sha256_fingerprint,
                        subject: c.subject,
                        issuer: c.issuer,
                    },
                    validity: d::ValidityPeriod {
                        not_before: date(&c.not_before)?,
                        not_after: date(&c.not_after)?,
                    },
                    is_self_signed: c.is_self_signed,
                    san: c.san,
                })
            })
            .transpose()?,
        capture: o.capture.map(decode_capture).transpose()?,
        raw_metadata: None,
    };
    observation.validate()?;
    Ok(observation)
}

fn encode_capture(c: &d::CaptureEvidence) -> Result<v1::CaptureEvidence, d::DomainError> {
    Ok(v1::CaptureEvidence {
        capture_sha256: c.capture_sha256.clone(),
        connection_uid: c.connection_uid.clone(),
        normalizer_version: c.normalizer_version.clone(),
        source_logs: c.source_logs.clone(),
        timeline: c
            .timeline
            .iter()
            .map(|e| {
                Ok(v1::TimelineEvent {
                    timestamp: format_date(e.timestamp)?,
                    kind: e.kind.clone(),
                    source: e.source.clone(),
                })
            })
            .collect::<Result<_, d::DomainError>>()?,
        gaps: c.gaps.clone(),
        tls_established: c.tls_established,
        protocol_hint: c.protocol_hint.map(|p| match p {
            d::EmailProtocol::Smtp => 1,
            d::EmailProtocol::Imap => 2,
            d::EmailProtocol::Pop3 => 3,
            d::EmailProtocol::Unknown => 4,
        }),
    })
}
fn decode_capture(c: v1::CaptureEvidence) -> Result<d::CaptureEvidence, d::DomainError> {
    Ok(d::CaptureEvidence {
        capture_sha256: c.capture_sha256,
        connection_uid: c.connection_uid,
        normalizer_version: c.normalizer_version,
        source_logs: c.source_logs,
        timeline: c
            .timeline
            .into_iter()
            .map(|e| {
                Ok(d::TimelineEvent {
                    timestamp: date(&e.timestamp)?,
                    kind: e.kind,
                    source: e.source,
                })
            })
            .collect::<Result<_, d::DomainError>>()?,
        gaps: c.gaps,
        tls_established: c.tls_established,
        protocol_hint: c.protocol_hint.map(|p| match p {
            1 => d::EmailProtocol::Smtp,
            2 => d::EmailProtocol::Imap,
            3 => d::EmailProtocol::Pop3,
            _ => d::EmailProtocol::Unknown,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn synthetic_contract_roundtrips_and_rejects_bad_versions() {
        for input in [
            include_str!("../../../fixtures/synthetic/smtp_tls10_legacy.json"),
            include_str!("../../../fixtures/synthetic/smtp_tls13_healthy.json"),
            include_str!("../../../fixtures/synthetic/smtp_cert_expired.json"),
            include_str!("../../../fixtures/synthetic/smtp_static_rsa.json"),
        ] {
            let observation: d::NormalizedObservation = serde_json::from_str(input).unwrap();
            let bytes = encode(&observation).unwrap();
            assert_eq!(decode(&bytes).unwrap(), observation);
            let mut envelope = v1::ObservationEnvelope::decode(bytes.as_slice()).unwrap();
            envelope.schema_version = 2;
            assert!(decode(&envelope.encode_to_vec()).is_err());
        }
        assert!(decode(&[]).is_err());
    }
    #[test]
    fn missing_and_unknown_evidence_remains_unknown() {
        let mut observation: d::NormalizedObservation = serde_json::from_str(include_str!(
            "../../../fixtures/synthetic/smtp_tls13_healthy.json"
        ))
        .unwrap();
        observation.starttls_state = None;
        observation.certificate = None;
        observation.tls_version = Some(d::TlsVersion::Unknown("future-tls".into()));
        observation.key_exchange = Some(d::KeyExchange::Unknown("future-kx".into()));
        assert_eq!(decode(&encode(&observation).unwrap()).unwrap(), observation);
        observation.raw_metadata = Some(serde_json::json!({"password": "must not leave sensor"}));
        assert!(encode(&observation).is_err());
    }
}
