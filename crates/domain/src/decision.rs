use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::finding::FindingCandidate;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityLevel {
    Low,
    Normal,
    High,
    Immediate,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionContext {
    pub session_id: Uuid,
    pub findings: Vec<FindingCandidate>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionResult {
    pub risk: RiskLevel,
    pub anomalous: bool,
    pub human_review: bool,
    pub priority: PriorityLevel,
    pub confidence: f32,
    pub provider_info: String,
    #[serde(default)]
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub id: Uuid,
    pub session_id: Option<Uuid>,
    pub asset_id: Option<Uuid>,
    pub provider: String,
    pub model: String,
    pub decision: DecisionResult,
    pub latency_ms: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
}

/// Shared provenance marker for the local deterministic fallback, never an AI assessment.
pub const DETERMINISTIC_DECISION_PROVIDER: &str = "mailent-deterministic-fallback";
impl DecisionResult {
    pub fn is_deterministic(&self) -> bool {
        self.provider_info == DETERMINISTIC_DECISION_PROVIDER
    }
}
