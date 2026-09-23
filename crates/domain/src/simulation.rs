use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::finding::FindingSeverity;

/// Request to simulate a proposed policy against historical sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySimulationRequest {
    /// Name of the policy to test against (e.g., "high-security", "modern", "legacy-compatible").
    pub policy_name: String,
    /// Optional asset IDs to limit simulation scope. If omitted or empty, all assets are evaluated.
    #[serde(default)]
    pub target_asset_ids: Vec<Uuid>,
    /// Optional lookback window in hours. Default: all available historical sessions.
    pub lookback_hours: Option<u32>,
}

/// Compatibility classification of an asset under a simulated policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetCompatibility {
    /// All evaluated sessions have complete evidence and satisfy the proposed policy.
    Compatible,
    /// At least one observed session violates a requirement in the proposed policy.
    WouldFail,
    /// No sessions or insufficient cryptographic evidence (e.g. missing handshake or unobserved transport).
    InsufficientEvidence,
}

impl std::fmt::Display for AssetCompatibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Compatible => write!(f, "Compatible"),
            Self::WouldFail => write!(f, "Would Fail"),
            Self::InsufficientEvidence => write!(f, "Unknown / Insufficient Evidence"),
        }
    }
}

/// A specific failure reason / deprecated dependency detected during simulation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimulationBreakage {
    pub rule_id: String,
    pub severity: FindingSeverity,
    pub title: String,
    pub description: String,
    pub remediation: String,
    pub deprecated_behavior: String,
    pub affected_sessions_count: usize,
    pub sample_flow: String,
}

/// Per-asset simulation result explaining whether the asset would survive the proposed policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssetSimulationResult {
    pub asset_id: Uuid,
    pub primary_name: String,
    pub addresses: Vec<String>,
    pub compatibility: AssetCompatibility,
    pub evaluated_sessions_count: usize,
    pub breakages: Vec<SimulationBreakage>,
    pub explanation: String,
}

/// Aggregated count of how often a specific breaking reason occurred across infrastructure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BreakageSummary {
    pub rule_id: String,
    pub deprecated_behavior: String,
    pub affected_assets_count: usize,
    pub affected_sessions_count: usize,
    pub description: String,
}

/// Complete result of a Crypto Digital Twin policy simulation run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicySimulationResult {
    pub id: Uuid,
    pub policy_name: String,
    pub policy_version: String,
    pub policy_description: String,
    pub total_assets: usize,
    pub compatible_assets_count: usize,
    pub would_fail_assets_count: usize,
    pub insufficient_evidence_assets_count: usize,
    pub total_sessions_evaluated: usize,
    pub breakage_summaries: Vec<BreakageSummary>,
    pub asset_results: Vec<AssetSimulationResult>,
    #[serde(with = "time::serde::rfc3339")]
    pub simulated_at: OffsetDateTime,
}
