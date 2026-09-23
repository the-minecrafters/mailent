//! Forensic reporting: one canonical model, deterministic builders, and
//! JSON / HTML / PDF export. All content derives from Mailent's own persisted
//! evidence; AI output is only ever carried as clearly labelled supplemental
//! context.
//!
//! The legacy [`ReportModel`] summary is kept for backward compatibility with
//! the previous metrics surface.
pub mod builder;
pub mod export;
pub mod model;

pub use builder::{ReportInput, build_report};
pub use export::{ReportError, render_html, render_pdf, to_json};
pub use model::{
    ActiveVerificationSection, AiAssessmentSection, CaseMetadata, CertificateSection,
    ContextSection, FindingSection, ForensicReport, Maybe, ProvenanceClass, RiskPrioritization,
    SessionRecord, TimelineEntry, UnavailableReason,
};

use mailent_domain::Finding;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_sessions_analyzed: u64,
    pub total_findings: u64,
    pub critical_findings: u64,
    pub high_findings: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportModel {
    pub title: String,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub summary: ReportSummary,
    pub findings: Vec<Finding>,
}

impl ReportModel {
    pub fn new(title: impl Into<String>, findings: Vec<Finding>, total_sessions: u64) -> Self {
        let critical_findings = findings
            .iter()
            .filter(|f| f.severity == mailent_domain::FindingSeverity::Critical)
            .count() as u64;
        let high_findings = findings
            .iter()
            .filter(|f| f.severity == mailent_domain::FindingSeverity::High)
            .count() as u64;

        Self {
            title: title.into(),
            generated_at: OffsetDateTime::now_utc(),
            summary: ReportSummary {
                total_sessions_analyzed: total_sessions,
                total_findings: findings.len() as u64,
                critical_findings,
                high_findings,
            },
            findings,
        }
    }

    pub fn to_json(&self) -> Result<String, ReportError> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}
