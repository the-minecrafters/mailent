use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Evidence for application-layer protocol identification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolEvidence {
    pub protocol: String,
    pub role: String,
    pub proof: String,
    pub verified_by: String,
}

/// First-class persistent forensic assessment record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssessmentRecord {
    pub id: Uuid,
    pub title: String,
    pub capture_name: String,
    pub capture_hash: String,
    pub capture_size_bytes: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub time_range_start: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub time_range_end: Option<OffsetDateTime>,
    pub protocols_identified: Vec<String>,
    pub protocol_evidence: Vec<ProtocolEvidence>,
    pub session_ids: Vec<Uuid>,
    pub asset_ids: Vec<Uuid>,
    pub finding_ids: Vec<Uuid>,
    pub posture_score: f32,
    pub posture_grade: String,
    pub evidence_gaps: Vec<String>,
    pub ai_risk_classification: String,
    pub ai_risk_rationale: String,
    pub ai_confidence: f32,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Brief summary of an assessment for listings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssessmentSummary {
    pub id: Uuid,
    pub title: String,
    pub capture_name: String,
    pub capture_hash: String,
    pub capture_size_bytes: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub protocols_identified: Vec<String>,
    pub session_count: usize,
    pub finding_count: usize,
    pub posture_score: f32,
    pub posture_grade: String,
    pub ai_risk_classification: String,
}

impl From<&AssessmentRecord> for AssessmentSummary {
    fn from(r: &AssessmentRecord) -> Self {
        Self {
            id: r.id,
            title: r.title.clone(),
            capture_name: r.capture_name.clone(),
            capture_hash: r.capture_hash.clone(),
            capture_size_bytes: r.capture_size_bytes,
            created_at: r.created_at,
            protocols_identified: r.protocols_identified.clone(),
            session_count: r.session_ids.len(),
            finding_count: r.finding_ids.len(),
            posture_score: r.posture_score,
            posture_grade: r.posture_grade.clone(),
            ai_risk_classification: r.ai_risk_classification.clone(),
        }
    }
}
