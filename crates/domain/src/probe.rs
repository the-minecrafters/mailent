use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    cert::CertificateObservation,
    intelligence::{DaneStatus, MtaStsMode},
    protocol::{EmailProtocol, StartTlsState},
    tls::{CipherSuite, ForwardSecrecyState, TlsVersion},
};

/// What caused this probe to be scheduled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeTrigger {
    /// An analyst explicitly requested a probe via API or CLI.
    ManualAnalyst,
    /// An `InternalExternalInconsistency` anomaly was detected.
    InternalExternalInconsistency,
    /// A certificate change was observed.
    CertificateChange,
    /// A STARTTLS regression was detected.
    StartTlsRegression,
    /// Scheduled periodic reverification (once per cooldown period).
    Scheduled,
}

impl std::fmt::Display for ProbeTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| "unknown".to_string());
        write!(f, "{}", s)
    }
}

/// Whether the active probe connected successfully and completed the protocol exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    Success,
    Timeout,
    ConnectionRefused,
    HandshakeError,
    ScopeRejected,
    InternalError,
}

/// STARTTLS capability observed during an active probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStartTlsResult {
    /// Server advertised STARTTLS in EHLO and accepted the STARTTLS command.
    AdvertisedAndAccepted,
    /// Server advertised STARTTLS in EHLO but rejected the upgrade command.
    AdvertisedAndRejected,
    /// Server did not list STARTTLS in its EHLO capabilities.
    NotAdvertised,
    /// Connection failed before EHLO/capability exchange.
    NotReached,
    ImplicitTls,
    AcceptedHandshakeFailed,
}

/// How a particular dimension differs between passive observation and active probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MismatchKind {
    TlsVersion,
    CipherFamily,
    CertificateFingerprint,
    CertificateIssuer,
    StartTlsPresence,
    DaneResult,
    MtaStsResult,
}

/// A single detected discrepancy between passive and active perspectives.
///
/// A `PerspectiveMismatch` is an observed fact — not a policy finding and not a
/// labelled attack classification.  It represents evidence that may warrant further
/// investigation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerspectiveMismatch {
    pub kind: MismatchKind,
    pub passive_value: String,
    pub active_value: String,
    pub description: String,
}

/// Structured result of one active verification run.
///
/// All fields represent observed facts. No "secure/insecure" boolean is produced.
/// Policy evaluation remains in the deterministic policy engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeResult {
    /// Resolved MX hostname (or explicit target for implicit-TLS endpoints).
    pub resolved_host: String,
    /// IP address actually connected to.
    pub resolved_ip: Option<String>,
    /// SMTP greeting banner.
    pub smtp_greeting: Option<String>,
    /// EHLO capabilities advertised by the server.
    pub ehlo_capabilities: Vec<String>,
    /// STARTTLS negotiation outcome.
    pub starttls: ProbeStartTlsResult,
    /// TLS version negotiated, if TLS was established.
    pub tls_version: Option<TlsVersion>,
    /// Cipher suite negotiated.
    pub cipher_suite: Option<CipherSuite>,
    /// Forward secrecy classification.
    pub forward_secrecy: ForwardSecrecyState,
    /// Certificate chain leaf, if TLS was established.
    pub certificate: Option<CertificateObservation>,
    /// Whether the certificate hostname validates against the connected host.
    pub certificate_hostname_valid: Option<bool>,
    /// MTA-STS expectation versus observed session outcome.
    pub mta_sts_mode: Option<MtaStsMode>,
    /// MTA-STS match / mismatch text description.
    pub mta_sts_result: Option<String>,
    /// DANE verification status.
    pub dane_status: DaneStatus,
    /// DANE result description.
    pub dane_result: Option<String>,
    /// Round-trip probe duration in milliseconds.
    pub latency_ms: u64,
    /// Non-fatal warnings accumulated during the probe.
    pub warnings: Vec<String>,
    /// Fatal error message when `outcome != Success`.
    pub error: Option<String>,
    #[serde(default)]
    pub certificate_trusted: Option<bool>,
    #[serde(default)]
    pub tls_challenges: Vec<crate::TlsChallenge>,
    /// Ephemeral input for existing DANE validation; not part of persisted/public evidence.
    #[serde(skip)]
    pub certificate_der: Vec<u8>,
    #[serde(skip)]
    pub spki_der: Vec<u8>,
    #[serde(default)]
    pub verification: Option<ProbeVerification>,
}

/// A single active probe run persisted against an asset.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeRun {
    pub id: Uuid,
    #[serde(default)]
    pub remediation_id: Option<Uuid>,
    #[serde(default)]
    pub verification_condition: Option<crate::RemediationCondition>,
    /// Asset this probe belongs to.
    pub asset_id: Uuid,
    /// Domain or host probed.
    pub target: String,
    /// Protocol probed (SMTP STARTTLS, SMTPS, IMAPS, POP3S).
    pub protocol: EmailProtocol,
    /// Port probed.
    pub port: u16,
    /// What scheduled or triggered this probe.
    pub trigger: ProbeTrigger,
    /// Investigation attached to this run, if triggered from an incident.
    pub investigation_id: Option<Uuid>,
    /// When the probe started.
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    /// When the probe finished.
    #[serde(with = "time::serde::rfc3339::option")]
    pub finished_at: Option<OffsetDateTime>,
    /// High-level outcome.
    pub outcome: ProbeOutcome,
    /// Detailed structured result, present when `outcome == Success`.
    pub result: Option<ProbeResult>,
    /// Differences detected between this active result and the most recent
    /// passive observation for the same asset.
    pub perspective_mismatches: Vec<PerspectiveMismatch>,
    /// True if at least one `PerspectiveMismatch` was found.
    pub has_mismatch: bool,
}

impl ProbeRun {
    pub fn new(
        asset_id: Uuid,
        target: String,
        protocol: EmailProtocol,
        port: u16,
        trigger: ProbeTrigger,
        investigation_id: Option<Uuid>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            remediation_id: None,
            verification_condition: None,
            asset_id,
            target,
            protocol,
            port,
            trigger,
            investigation_id,
            started_at: OffsetDateTime::now_utc(),
            finished_at: None,
            outcome: ProbeOutcome::InternalError,
            result: None,
            perspective_mismatches: Vec::new(),
            has_mismatch: false,
        }
    }

    pub fn finish(&mut self, outcome: ProbeOutcome, result: Option<ProbeResult>) {
        self.finished_at = Some(OffsetDateTime::now_utc());
        self.outcome = outcome;
        self.result = result;
    }

    pub fn attach_mismatches(&mut self, mismatches: Vec<PerspectiveMismatch>) {
        self.has_mismatch = !mismatches.is_empty();
        self.perspective_mismatches = mismatches;
    }
}

/// Request body for `POST /api/v1/assets/{id}/probe`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeRequest {
    /// Optional explicit port override.  Defaults to 25 for SMTP, 465 for SMTPS, etc.
    pub port: Option<u16>,
    #[serde(default)]
    pub investigation_id: Option<Uuid>,
    /// Protocol to probe.
    #[serde(default)]
    pub protocol: Option<EmailProtocol>,
    /// Trigger reason for audit logging.
    #[serde(default)]
    pub trigger: Option<ProbeTrigger>,
}

/// Compare the active result with the most recent passive session and
/// return any `PerspectiveMismatch` differences found.
///
/// This is pure comparison logic — no policy evaluation, no labelling.
pub fn compare_perspectives(
    active: &ProbeResult,
    passive_session: &crate::session::EmailSession,
) -> Vec<PerspectiveMismatch> {
    let mut mismatches = Vec::new();

    // TLS version
    if let (Some(active_ver), Some(passive_ver)) =
        (&active.tls_version, &passive_session.tls_version)
        && active_ver != passive_ver
    {
        mismatches.push(PerspectiveMismatch {
            kind: MismatchKind::TlsVersion,
            passive_value: passive_ver.to_string(),
            active_value: active_ver.to_string(),
            description: format!(
                "Passive observation saw {passive_ver}; active probe negotiated {active_ver}"
            ),
        });
    }

    // Certificate fingerprint
    if let (Some(active_cert), Some(passive_cert)) =
        (&active.certificate, &passive_session.certificate)
    {
        if active_cert.reference.sha256_fingerprint != passive_cert.reference.sha256_fingerprint {
            mismatches.push(PerspectiveMismatch {
                kind: MismatchKind::CertificateFingerprint,
                passive_value: passive_cert.reference.sha256_fingerprint.clone(),
                active_value: active_cert.reference.sha256_fingerprint.clone(),
                description: "Active probe observed a different certificate than the passively captured session".to_string(),
            });
        }
        // Certificate issuer (even if fingerprint matched — useful standalone)
        if active_cert.reference.issuer != passive_cert.reference.issuer {
            mismatches.push(PerspectiveMismatch {
                kind: MismatchKind::CertificateIssuer,
                passive_value: passive_cert.reference.issuer.clone(),
                active_value: active_cert.reference.issuer.clone(),
                description:
                    "Certificate issuer differs between passive observation and active probe"
                        .to_string(),
            });
        }
    }

    if let (Some(a), Some(p)) = (&active.cipher_suite, &passive_session.cipher_suite)
        && a.name != p.name
    {
        mismatches.push(PerspectiveMismatch {
            kind: MismatchKind::CipherFamily,
            passive_value: p.name.clone(),
            active_value: a.name.clone(),
            description: "Negotiated ciphers differ; clients may offer different capabilities"
                .into(),
        });
    }
    let a = match active.starttls {
        ProbeStartTlsResult::NotAdvertised => Some(false),
        ProbeStartTlsResult::AdvertisedAndAccepted
        | ProbeStartTlsResult::AdvertisedAndRejected
        | ProbeStartTlsResult::AcceptedHandshakeFailed => Some(true),
        _ => None,
    };
    let p = match passive_session.starttls_state {
        Some(StartTlsState::NotAdvertised) => Some(false),
        Some(
            StartTlsState::Advertised
            | StartTlsState::AdvertisedNotUsed
            | StartTlsState::AdvertisedAndUsed
            | StartTlsState::Accepted
            | StartTlsState::TlsStarted
            | StartTlsState::TlsEstablished,
        ) => Some(true),
        _ => None,
    };
    if let (Some(a), Some(p)) = (a, p)
        && a != p
    {
        mismatches.push(PerspectiveMismatch {
            kind: MismatchKind::StartTlsPresence,
            passive_value: p.to_string(),
            active_value: a.to_string(),
            description: "STARTTLS advertisement differs between perspectives".into(),
        });
    }
    mismatches
}

/// Evidence links preserve passive facts and explain what one active vantage point verified.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeVerification {
    pub passive_session_id: Option<Uuid>,
    pub confidence: String,
    pub drift: Vec<ProbeDriftVerification>,
    pub anomaly_ids: Vec<Uuid>,
    #[serde(default)]
    pub anomalies: Vec<ProbeAnomalyVerification>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeDriftVerification {
    pub drift_id: Uuid,
    pub active_value: String,
    pub confirmed: bool,
}

impl ProbeResult {
    pub fn unavailable(host: &str, error: Option<String>) -> Self {
        Self {
            resolved_host: host.into(),
            resolved_ip: None,
            smtp_greeting: None,
            ehlo_capabilities: vec![],
            starttls: ProbeStartTlsResult::NotReached,
            tls_version: None,
            cipher_suite: None,
            forward_secrecy: ForwardSecrecyState::Unknown,
            certificate: None,
            certificate_hostname_valid: None,
            certificate_trusted: None,
            tls_challenges: vec![],
            mta_sts_mode: None,
            mta_sts_result: None,
            dane_status: DaneStatus::DaneUnverifiable,
            dane_result: None,
            latency_ms: 0,
            warnings: vec![],
            error,
            certificate_der: vec![],
            spki_der: vec![],
            verification: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeAnomalyVerification {
    pub anomaly_id: Uuid,
    pub active_value: String,
    /// Corroborated, perspective_mismatch, or unavailable; one probe cannot verify a rate.
    pub conclusion: String,
}
