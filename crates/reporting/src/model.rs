//! Canonical forensic report model.
//!
//! One model, three export formats (JSON / HTML / PDF). Every section is built
//! exclusively from Mailent's own persisted evidence; unavailable evidence is
//! represented honestly (`None` → "unavailable"), never inferred. AI/Jev
//! context, when present, is carried in a clearly labelled supplemental
//! section and never alters deterministic content.
use mailent_domain::{CertificateCryptoDetails, RemediationGuidance, SecurityPosture};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// What a piece of reported content is derived from. Reports must make the
/// epistemic status of every statement explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceClass {
    /// Observed directly from captures or active probes.
    ObservedFact,
    /// Output of the deterministic policy engine (rule ID + policy version).
    DeterministicFinding,
    /// Baseline deviation; context, not a policy verdict.
    AnomalyContext,
    /// Evidence collected by an explicitly authorized active probe.
    ActiveVerification,
    /// Supplemental Jev/LLM output, clearly identified, never source of truth.
    AiAssessment,
}

impl std::fmt::Display for ProvenanceClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ObservedFact => write!(f, "observed fact"),
            Self::DeterministicFinding => write!(f, "deterministic finding"),
            Self::AnomalyContext => write!(f, "anomaly context"),
            Self::ActiveVerification => write!(f, "active verification"),
            Self::AiAssessment => write!(f, "AI assessment (supplemental)"),
        }
    }
}

/// Why a value is absent in the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableReason {
    /// The capture or probe did not produce this evidence.
    NotCaptured,
    /// Evidence exists but could not be parsed (reported, never guessed).
    NotParseable,
    /// No authorized active probe ran, so the fact is only verifiable actively.
    RequiresActiveVerification,
}

impl UnavailableReason {
    pub fn render(self) -> &'static str {
        match self {
            Self::NotCaptured => "unavailable (not captured)",
            Self::NotParseable => "unavailable (not parseable from evidence)",
            Self::RequiresActiveVerification => "unavailable (requires active verification)",
        }
    }
}

/// A value that is either present or honestly unavailable.
pub type Maybe<T> = Option<T>;

/// Case metadata identifying what was analyzed and how it can be reproduced.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaseMetadata {
    pub title: String,
    pub report_id: String,
    /// Subject scope: investigation id and/or asset identity.
    pub investigation_id: Option<uuid::Uuid>,
    pub asset_id: Option<uuid::Uuid>,
    pub asset_name: Maybe<String>,
    pub asset_addresses: Vec<String>,
    /// Capture hashes covered by this report (SHA-256 of source captures).
    pub capture_sha256: Vec<String>,
    /// Time window covered by the underlying sessions.
    pub window_start: Maybe<OffsetDateTime>,
    pub window_end: Maybe<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    /// Which deterministic artifacts the content derives from.
    pub policy_name: String,
    pub policy_version: String,
    pub posture_score_version: String,
    /// Mailent version that produced the report.
    pub generator: String,
}

/// One reconstructed session in compact, report-appropriate form.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: uuid::Uuid,
    pub protocol: String,
    /// e.g. "SMTP (capture hint: Smtp)".
    pub protocol_identification: String,
    pub flow: String,
    pub starttls_transitions: Vec<String>,
    pub tls_version: Maybe<String>,
    pub cipher_suite: Maybe<String>,
    pub key_exchange: Maybe<String>,
    pub forward_secrecy: Maybe<String>,
    pub certificate_summary: Maybe<CertificateSection>,
    /// Capture timeline kinds, preserving source attribution.
    pub timeline: Vec<TimelineEntry>,
    /// Explicit capture gaps (honest visibility limits).
    pub gaps: Vec<String>,
    /// Sensor + parser provenance for this session.
    pub provenance: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: OffsetDateTime,
    pub kind: String,
    pub source: String,
}

/// Certificate section: observed identity/validity plus crypto details.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CertificateSection {
    pub subject: String,
    pub issuer: String,
    pub sha256_fingerprint: String,
    pub not_before: Maybe<OffsetDateTime>,
    pub not_after: Maybe<OffsetDateTime>,
    pub san: Vec<String>,
    pub is_self_signed: Maybe<bool>,
    /// Validity state relative to the observation time.
    pub expiry_state: String,
    /// Extended crypto details; each field individually honest about absence.
    pub crypto_details: Maybe<CertificateCryptoDetails>,
    /// Where this certificate evidence came from.
    pub source: ProvenanceClass,
}

/// One policy finding with its evidence and remediation linkage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingSection {
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub category: String,
    pub description: String,
    pub policy_name: String,
    pub policy_version: String,
    pub reference: String,
    pub evidence: Vec<mailent_domain::EvidenceRef>,
    pub remediation_id: Maybe<uuid::Uuid>,
    pub provenance: ProvenanceClass,
}

/// Anomaly or drift context, clearly not a policy verdict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextSection {
    pub kind: String, // "anomaly" or "drift"
    pub signal: String,
    pub title: String,
    pub detail: String,
    pub baseline_value: Maybe<String>,
    pub current_value: Maybe<String>,
    pub observed_at: Maybe<OffsetDateTime>,
    pub provenance: ProvenanceClass,
}

/// Active verification evidence attributed to its probe run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActiveVerificationSection {
    pub probe_id: uuid::Uuid,
    pub target: String,
    pub protocol: String,
    pub port: u16,
    pub trigger: String,
    pub outcome: String,
    pub started_at: OffsetDateTime,
    pub finished_at: Maybe<OffsetDateTime>,
    pub tls_version: Maybe<String>,
    pub forward_secrecy: Maybe<String>,
    pub starttls_result: Maybe<String>,
    pub certificate_hostname_valid: Maybe<bool>,
    pub perspective_mismatches: Vec<String>,
    /// What this verification corroborated or refuted, in the probe's own words.
    pub verification_summary: Vec<String>,
    pub provenance: ProvenanceClass,
}

/// Clearly-labelled supplemental AI assessment. Copied verbatim from the
/// stored decision record; it never changes deterministic content.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiAssessmentSection {
    pub provider: String,
    pub model: String,
    pub risk: Maybe<String>,
    pub priority: Maybe<String>,
    pub confidence: Maybe<f32>,
    pub reasons: Vec<String>,
    pub caveat: String,
    pub provenance: ProvenanceClass,
}

/// Risk prioritization derived deterministically from findings + posture.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskPrioritization {
    pub grade: String,
    pub score: f32,
    pub score_capped: bool,
    /// Ordered action list: worst finding first.
    pub prioritized_actions: Vec<String>,
}

/// The canonical forensic report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForensicReport {
    pub metadata: CaseMetadata,
    pub posture: Maybe<SecurityPosture>,
    pub risk: Maybe<RiskPrioritization>,
    pub sessions: Vec<SessionRecord>,
    pub certificates: Vec<CertificateSection>,
    pub findings: Vec<FindingSection>,
    pub context: Vec<ContextSection>,
    pub active_verifications: Vec<ActiveVerificationSection>,
    pub remediation: Vec<RemediationGuidance>,
    #[serde(default)]
    pub remediation_lifecycle: Vec<mailent_domain::RemediationRecord>,
    pub best_practices: Vec<RemediationGuidance>,
    pub ai_assessment: Maybe<AiAssessmentSection>,
    /// Explicit statement of evidence that was NOT available, with reasons.
    pub evidence_gaps: Vec<String>,
}

impl ForensicReport {
    /// Stable content fingerprint: canonical JSON of all content except
    /// `metadata.generated_at`, hashed with SHA-256. Identical evidence always
    /// produces an identical fingerprint regardless of generation time.
    pub fn content_fingerprint(&self) -> String {
        let mut clone = self.clone();
        clone.metadata.generated_at = OffsetDateTime::UNIX_EPOCH;
        let json = serde_json::to_string(&clone).unwrap_or_default();
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(json.as_bytes()))
    }
}
