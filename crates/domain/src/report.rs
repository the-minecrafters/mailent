use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::posture::PostureSubjectKind;

/// Summary of a frozen/archived report case snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArchivedReportSummary {
    pub id: Uuid,
    pub report_id: String,
    pub subject_kind: PostureSubjectKind,
    pub subject_id: Uuid,
    pub title: String,
    pub fingerprint: String,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub archived_at: OffsetDateTime,
    pub archived_by: String,
    pub notes: Option<String>,
}

/// Full record of a frozen/archived report case snapshot with immutable canonical JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArchivedReportRecord {
    pub id: Uuid,
    pub report_id: String,
    pub subject_kind: PostureSubjectKind,
    pub subject_id: Uuid,
    pub title: String,
    pub fingerprint: String,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub archived_at: OffsetDateTime,
    pub archived_by: String,
    pub notes: Option<String>,
    /// Full serialized canonical ForensicReport model frozen at archive time.
    pub raw_report_json: String,
}

/// Request to freeze a report for an asset or investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveReportRequest {
    pub subject_kind: PostureSubjectKind,
    pub subject_id: Uuid,
    pub notes: Option<String>,
    pub archived_by: Option<String>,
}
