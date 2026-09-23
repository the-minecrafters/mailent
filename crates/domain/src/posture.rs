use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::finding::{FindingCategory, FindingSeverity};

/// Semantic version of the deterministic posture scoring model.
///
/// Bump when weights, category logic, or cap semantics change so any historical
/// score can be interpreted against the exact model that produced it.
pub const POSTURE_SCORE_VERSION: &str = "1.0.0";

/// Weights used by the scoring model. Public so scores are fully explainable
/// and reproducible against a published configuration.
pub fn category_weight(category: PostureCategory) -> f32 {
    match category {
        PostureCategory::TransportSecurity => 0.40,
        PostureCategory::CertificateHygiene => 0.25,
        PostureCategory::ProtocolConfiguration => 0.25,
        PostureCategory::AnomalyRiskContext => 0.10,
    }
}

/// Score dimensions exposed as category breakdowns.
/// Weights sum to 1.0 (see `CATEGORY_WEIGHTS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureCategory {
    TransportSecurity,
    CertificateHygiene,
    ProtocolConfiguration,
    AnomalyRiskContext,
}

impl PostureCategory {
    pub fn weight(self) -> f32 {
        crate::posture::category_weight(self)
    }
}

impl std::fmt::Display for PostureCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TransportSecurity => write!(f, "Transport Security"),
            Self::CertificateHygiene => write!(f, "Certificate Hygiene"),
            Self::ProtocolConfiguration => write!(f, "Protocol & Configuration"),
            Self::AnomalyRiskContext => write!(f, "Anomaly & Risk Context"),
        }
    }
}

/// Qualitative posture grade derived from the numeric score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureGrade {
    Critical,
    Weak,
    Moderate,
    Good,
    Strong,
}

impl PostureGrade {
    /// Deterministic mapping from a 0..=100 score to a qualitative grade.
    pub fn from_score(score: f32) -> Self {
        if score >= 90.0 {
            Self::Strong
        } else if score >= 75.0 {
            Self::Good
        } else if score >= 55.0 {
            Self::Moderate
        } else if score >= 30.0 {
            Self::Weak
        } else {
            Self::Critical
        }
    }
}

impl std::fmt::Display for PostureGrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Strong => write!(f, "Strong"),
            Self::Good => write!(f, "Good"),
            Self::Moderate => write!(f, "Moderate"),
            Self::Weak => write!(f, "Weak"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// One weighted category with its contributing score and the finding rule IDs
/// that drove deductions in this category (explainability + traceability).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostureCategoryScore {
    pub category: PostureCategory,
    /// Category-local score 0..=100 before weighting.
    pub score: f32,
    pub weight: f32,
    /// Weighted contribution of this category to the composite score.
    pub weighted_score: f32,
    pub finding_rule_ids: Vec<String>,
    /// Human-readable explanation of how this category score was derived.
    pub rationale: String,
}

/// Deduction applied by a specific finding to a specific category.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostureDeduction {
    pub rule_id: String,
    pub finding_id: Uuid,
    pub severity: FindingSeverity,
    pub category: PostureCategory,
    /// Points removed from the category's base score by this finding.
    pub points: f32,
    pub evidence_description: String,
}

/// Deterministic, versioned, explainable security posture for one subject
/// (asset, session, or investigation).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityPosture {
    /// Stable, deterministic UUID (v5) derived from subject + evidence content.
    pub id: Uuid,
    /// Scoring model version (`POSTURE_SCORE_VERSION`).
    pub score_version: String,
    /// What kind of subject the posture describes.
    pub subject_kind: PostureSubjectKind,
    /// ID of the subject (asset id, session id, or investigation id).
    pub subject_id: Uuid,
    /// Composite weighted score 0..=100.
    pub score: f32,
    pub grade: PostureGrade,
    /// Cap applied when serious findings would otherwise hide behind a high average.
    pub score_capped: bool,
    /// Composite score before the cap was applied (equals `score` when uncapped).
    pub pre_cap_score: f32,
    pub categories: Vec<PostureCategoryScore>,
    pub deductions: Vec<PostureDeduction>,
    /// Rule IDs of the most severe findings factored into this score.
    pub worst_findings: Vec<String>,
    /// Count of findings that contributed deductions.
    pub findings_considered: usize,
    #[serde(with = "time::serde::rfc3339")]
    pub computed_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureSubjectKind {
    Asset,
    Session,
    Investigation,
}

/// Kind of guidance Mailent produced from observed evidence.
///
/// `Remediation` and `BestPractice` are deliberately distinct types so actual
/// vulnerabilities can never be rendered as advice-and-chill, and hardening
/// advice is never mistaken for an active vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuidanceKind {
    /// A deterministic policy finding was observed; this is how to fix it.
    Remediation,
    /// The asset is not (yet) in violation; this is contextual hardening advice.
    BestPractice,
}

/// Evidence-backed actionable guidance for one finding (or one improvement
/// opportunity). All observed values come from Mailent's own evidence, never
/// from generic templates alone.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemediationGuidance {
    pub id: Uuid,
    pub kind: GuidanceKind,
    /// Finding this guidance addresses (empty for best-practice entries).
    pub finding_id: Option<Uuid>,
    pub rule_id: String,
    pub title: String,
    /// What Mailent actually observed (with observed values).
    pub observed: String,
    /// Why the current state matters (impact explanation).
    pub why_it_matters: String,
    /// What concretely should be changed.
    pub recommendation: String,
    /// The recommended secure end-state configuration.
    pub recommended_state: String,
    /// Compatibility/operational caveats derived from observed history, if any.
    pub compatibility_caveats: Vec<String>,
    /// How Mailent can verify the fix after remediation.
    pub verification: String,
    /// Evidence references that ground this guidance.
    pub evidence: Vec<crate::finding::EvidenceRef>,
    /// Severity of the underlying finding (best-practice entries carry `Low`).
    pub severity: FindingSeverity,
    /// Finding category the guidance maps to.
    pub category: FindingCategory,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

/// Deterministic hash-like identity input for scoring/guidance IDs so the same
/// evidence always produces the same UUID.
pub fn posture_uuid(namespace: Uuid, key: &str) -> Uuid {
    Uuid::new_v5(&namespace, key.as_bytes())
}
