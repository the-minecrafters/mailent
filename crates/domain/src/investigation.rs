use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::decision::{DecisionResult, PriorityLevel, RiskLevel};

/// Lifecycle state of an investigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvestigationStatus {
    Open,
    UnderReview,
    Resolved,
}

/// Correlated security incident grouping related policy findings, drift events,
/// baseline anomalies, external domain intelligence, and Jev risk assessments.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Investigation {
    pub id: Uuid,
    pub asset_id: Uuid,
    pub title: String,
    pub summary: String,
    pub status: InvestigationStatus,
    pub risk: RiskLevel,
    pub priority: PriorityLevel,
    pub finding_ids: Vec<String>,
    pub drift_event_ids: Vec<Uuid>,
    pub anomaly_ids: Vec<Uuid>,
    pub external_intelligence: serde_json::Value,
    pub jev_decision: Option<DecisionResult>,
    #[serde(with = "time::serde::rfc3339")]
    pub first_observed: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_observed: OffsetDateTime,
}
