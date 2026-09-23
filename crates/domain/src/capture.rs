//! Capture evidence shared by every ingestion path, with no parser dependency.
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineEvent {
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub kind: String,
    /// A source log and record number, not a manufactured explanation.
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureEvidence {
    pub capture_sha256: String,
    pub connection_uid: String,
    pub normalizer_version: String,
    pub source_logs: Vec<String>,
    pub timeline: Vec<TimelineEvent>,
    /// Explicit visibility gaps; empty does not imply full security validation.
    pub gaps: Vec<String>,
    pub tls_established: Option<bool>,
    /// A port-based hint is never substituted for an observed protocol.
    pub protocol_hint: Option<crate::EmailProtocol>,
}
