use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
};
use mailent_domain::AssessmentRecord;
use mailent_reporting::model::ForensicReport;
use mailent_scanner::DomainScanner;
use serde::{Deserialize, Serialize};

use crate::{auth::ExecutionContext, state::AppState};

#[derive(Debug, Deserialize)]
pub struct InfrastructureScanRequest {
    pub domain: String,
}

#[derive(Debug, Serialize)]
pub struct InfrastructureScanResponse {
    pub assessment: AssessmentRecord,
    pub report: ForensicReport,
    pub endpoints_checked: usize,
    pub endpoints_succeeded: usize,
    pub endpoints_failed: usize,
}

pub async fn scan_infrastructure_handler(
    State(state): State<AppState>,
    ctx: Option<Extension<ExecutionContext>>,
    Json(req): Json<InfrastructureScanRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let domain = req.domain.trim();
    if domain.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Domain cannot be empty".to_string(),
        ));
    }

    let scanner = DomainScanner::new_live().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Scanner init failed: {e}"),
        )
    })?;

    let scan_result = scanner
        .scan_domain(domain)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Scan failed: {e}")))?;

    let org_id = ctx.as_ref().and_then(|Extension(c)| c.organization_id);
    let mut assessment = scan_result.assessment;
    if let Some(oid) = org_id {
        assessment = assessment.with_organization(oid);
    }

    state
        .assessments
        .save(&assessment)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let raw_report_json = serde_json::to_string(&scan_result.report).unwrap_or_default();
    use sha2::Digest;
    let fingerprint = format!("{:x}", sha2::Sha256::digest(raw_report_json.as_bytes()));
    let archived_record = mailent_domain::ArchivedReportRecord {
        id: uuid::Uuid::new_v4(),
        report_id: scan_result.report.metadata.report_id.clone(),
        subject_kind: mailent_domain::PostureSubjectKind::Asset,
        subject_id: assessment
            .asset_ids
            .first()
            .copied()
            .unwrap_or(assessment.id),
        title: scan_result.report.metadata.title.clone(),
        fingerprint,
        generated_at: scan_result.report.metadata.generated_at,
        archived_at: time::OffsetDateTime::now_utc(),
        archived_by: "mailent-scanner".into(),
        notes: Some(format!("Infrastructure scan for domain {domain}")),
        raw_report_json,
    };
    let _ = state.archived_reports.archive(&archived_record).await;

    Ok((
        StatusCode::CREATED,
        Json(InfrastructureScanResponse {
            assessment,
            report: scan_result.report,
            endpoints_checked: scan_result.endpoints_checked,
            endpoints_succeeded: scan_result.endpoints_succeeded,
            endpoints_failed: scan_result.endpoints_failed,
        }),
    ))
}
