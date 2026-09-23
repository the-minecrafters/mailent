use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    baseline::AnomalySignal,
    decision::{PriorityLevel, RiskLevel},
    drift::{DriftEvent, DriftKind},
    finding::{Finding, FindingCategory, FindingSeverity},
    intelligence::MtaStsMode,
    probe::MismatchKind,
    protocol::{EmailProtocol, StartTlsState},
    tls::{ForwardSecrecyState, TlsVersion},
};

/// Version of the training data feature schema.  Bump only when existing
/// `TrainingFeatures` snapshots would be interpreted differently; snapshots
/// are stored verbatim at capture time so old records stay reproducible.
pub const TRAINING_FEATURE_SCHEMA_VERSION: u32 = 1;

/// A versioned training record captured at decision time, decoupled from any
/// model-training pipeline.  Analysts may attach an outcome label later.
///
/// The feature snapshot is frozen when the investigation is correlated:
/// the stored `features` are the *original* derived context, never recomputed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrainingRecord {
    pub id: Uuid,
    pub investigation_id: Uuid,
    pub asset_id: Uuid,
    pub feature_schema_version: u32,
    #[serde(with = "time::serde::rfc3339")]
    pub captured_at: OffsetDateTime,
    pub features: TrainingFeatures,
    /// Automated label produced at capture time.  Kept structurally separate
    /// from `analyst_label` so automated vs analyst/final labels never mix.
    pub automated_label: Option<AutomatedLabel>,
    /// Analyst or final outcome label, attached after capture.
    pub analyst_label: Option<AnalystLabel>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub labeled_at: Option<OffsetDateTime>,
}

/// The original, structured feature snapshot persisted at decision time.
///
/// Only derived features are stored: raw packets, mail bodies, credentials and
/// raw host/IP identity are excluded.  Domain names and certificate issuers are
/// reduced to hashes where possible.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrainingFeatures {
    pub asset: AssetFeatures,
    pub policy: Vec<PolicyFindingFeature>,
    pub baseline: Option<BaselineFeatures>,
    pub anomalies: Vec<AnomalyFeature>,
    pub tls: TlsFeatures,
    pub certificate: Option<CertificateFeature>,
    pub drift: Vec<DriftFeature>,
    /// MTA-STS / DANE / TLS-RPT context observed at decision time.
    pub delivery: DeliveryContextFeatures,
    /// Active probe verification available at capture time, if any.
    pub probe: Option<ProbeFeature>,
    /// Jev decision as a *teacher/context signal* — never ground truth.
    pub jev: Option<JevFeature>,
}

impl Default for TrainingFeatures {
    fn default() -> Self {
        Self {
            asset: AssetFeatures {
                endpoint_count: 0,
                protocols: Vec::new(),
                tls_versions: Vec::new(),
                cipher_suite_count: 0,
                certificate_count: 0,
                has_domain_name: false,
                name_hash: None,
            },
            policy: Vec::new(),
            baseline: None,
            anomalies: Vec::new(),
            tls: TlsFeatures {
                protocol: EmailProtocol::Smtp,
                port: 0,
                tls_version: None,
                cipher_name: None,
                forward_secrecy: ForwardSecrecyState::Unknown,
                starttls_state: None,
                tls_established: false,
            },
            certificate: None,
            drift: Vec::new(),
            delivery: DeliveryContextFeatures {
                dane_status: None,
                mta_sts_mode: None,
                mta_sts_enforced: false,
                mta_sts_failed: false,
                tlsa_record_count: 0,
                tls_rpt_policy_present: false,
            },
            probe: None,
            jev: None,
        }
    }
}

/// Asset-level derived context.  Hostnames and addresses are intentionally
/// reduced to counts and a stable name hash rather than raw identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssetFeatures {
    pub endpoint_count: usize,
    pub protocols: Vec<EmailProtocol>,
    pub tls_versions: Vec<TlsVersion>,
    pub cipher_suite_count: usize,
    pub certificate_count: usize,
    pub has_domain_name: bool,
    pub name_hash: Option<String>,
}

/// One deterministic policy finding, reduced to derived fields.  Prose/evidence
/// (which can embed addresses) is deliberately excluded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyFindingFeature {
    pub rule_id: String,
    pub policy_name: String,
    pub severity: FindingSeverity,
    pub category: FindingCategory,
}

/// Statistical baseline features that can feed offline training.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineFeatures {
    pub sample_count: u64,
    pub coverage: f32,
    pub starttls_success_rate: f32,
    pub handshake_failure_rate: f32,
    pub session_frequency_per_hour: f32,
    pub tls_version_distribution: HashMap<String, f32>,
    pub peer_count: usize,
    pub ports: Vec<u16>,
}

/// A single anomaly signal, reduced to its numeric/symbolic features.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnomalyFeature {
    pub signal: String,
    pub deviation: f32,
    pub confidence: f32,
}

/// TLS / STARTTLS state observed in the triggering session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TlsFeatures {
    pub protocol: EmailProtocol,
    pub port: u16,
    pub tls_version: Option<TlsVersion>,
    pub cipher_name: Option<String>,
    pub forward_secrecy: ForwardSecrecyState,
    pub starttls_state: Option<StartTlsState>,
    pub tls_established: bool,
}

/// Certificate signal, reduced to hashes and validity.  The SHA-256 fingerprint
/// itself is a hash and safe to persist as a derived feature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CertificateFeature {
    pub fingerprint_hash: String,
    pub issuer_hash: Option<String>,
    pub san_count: usize,
    pub validity_days_remaining: i64,
}

/// A drift signal as a tuple of (kind, value) — raw description prose excluded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DriftFeature {
    pub kind: DriftKind,
    pub new_value: Option<String>,
    pub had_previous_value: bool,
}

/// MTA-STS / DANE / TLS-RPT context observed at decision time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeliveryContextFeatures {
    pub dane_status: Option<String>,
    pub mta_sts_mode: Option<MtaStsMode>,
    pub mta_sts_enforced: bool,
    pub mta_sts_failed: bool,
    pub tlsa_record_count: usize,
    pub tls_rpt_policy_present: bool,
}

/// Active probe verification evidence, reduced to derived signals.  Raw target
/// host, resolved IP and SMTP prose are excluded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeFeature {
    pub protocol: EmailProtocol,
    pub port: u16,
    pub outcome: String,
    pub starttls: String,
    pub tls_version: Option<String>,
    pub dane_status: Option<String>,
    pub has_mismatch: bool,
    pub mismatch_kinds: Vec<MismatchKind>,
    pub verified_drift_count: usize,
    pub latency_ms: u64,
}

/// Jev decision captured as a teacher/context signal — not ground truth.
/// Analyst/final labels remain the authoritative outcome.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JevFeature {
    pub role: String,
    pub provider: String,
    pub risk: RiskLevel,
    pub anomalous: bool,
    pub human_review: bool,
    pub priority: PriorityLevel,
    pub confidence: f32,
}

/// Automated label produced at capture time by the decision path.
///
/// Structurally distinct from [`AnalystLabel`] — never overwritten by analyst
/// feedback, so automated and analyst signals remain separable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AutomatedLabel {
    /// `jev` or `deterministic_fallback`.
    pub source: String,
    pub risk: Option<RiskLevel>,
    pub priority: Option<PriorityLevel>,
    pub anomalous: bool,
    pub human_review: bool,
}

/// Analyst / final outcome category, distinguishable from automated labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalystOutcome {
    AnalystReviewed,
    BenignExpectedChange,
    RealMisconfiguration,
    FalsePositive,
    RequiresRemediation,
    Dismissed,
    Remediated,
}

impl std::fmt::Display for AnalystOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| "analyst_reviewed".to_string());
        write!(f, "{s}")
    }
}

/// Analyst-attached outcome label.  `priority` lets an analyst override the
/// automated priority; `label_source` distinguishes analyst vs final decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalystLabel {
    pub outcome: AnalystOutcome,
    /// Priority chosen by the analyst, overriding the automated default.
    #[serde(default)]
    pub priority: Option<PriorityLevel>,
    pub label_source: String,
    pub note: Option<String>,
    pub labeled_by: Option<String>,
}

impl TrainingRecord {
    pub fn new(
        investigation_id: Uuid,
        asset_id: Uuid,
        captured_at: OffsetDateTime,
        features: TrainingFeatures,
        automated_label: Option<AutomatedLabel>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            investigation_id,
            asset_id,
            feature_schema_version: TRAINING_FEATURE_SCHEMA_VERSION,
            captured_at,
            features,
            automated_label,
            analyst_label: None,
            labeled_at: None,
        }
    }
}

impl From<&Finding> for PolicyFindingFeature {
    fn from(f: &Finding) -> Self {
        Self {
            rule_id: f.rule_id.clone(),
            policy_name: f.policy_name.clone(),
            severity: f.severity,
            category: f.category,
        }
    }
}

impl From<&AnomalySignal> for AnomalyFeature {
    fn from(a: &AnomalySignal) -> Self {
        Self {
            signal: a.signal.clone(),
            deviation: a.deviation,
            confidence: a.confidence,
        }
    }
}

impl From<&DriftEvent> for DriftFeature {
    fn from(d: &DriftEvent) -> Self {
        Self {
            kind: d.kind.clone(),
            new_value: Some(d.new_value.clone()),
            had_previous_value: d.previous_value.is_some(),
        }
    }
}

/// Stable, deterministic hash used to store derived identity instead of the
/// raw host/issuer string.  Cross-process stable via `DefaultHasher::new`.
pub fn name_hash(value: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}
