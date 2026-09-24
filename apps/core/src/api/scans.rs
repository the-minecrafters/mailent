use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use mailent_domain::{AgentJob, AssessmentRecord};
use mailent_reporting::model::ForensicReport;
use mailent_scanner::DomainScanner;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

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

    let mut scan_result = scanner
        .scan_domain(domain)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Scan failed: {e}")))?;

    let org_id = ctx.as_ref().and_then(|Extension(c)| c.organization_id);
    let mut assessment = scan_result.assessment;
    if let Some(oid) = org_id {
        assessment = assessment.with_organization(oid);
    }
    for finding in &mut scan_result.findings {
        finding.organization_id = org_id;
        state
            .findings
            .save(finding.clone())
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    for session in scan_result.sessions {
        state
            .sessions
            .save(session)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
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

#[derive(Debug, Deserialize)]
pub struct DeviceScanRequest {
    pub domain: String,
    pub device_id: Uuid,
}

/// Dispatch only typed domain checks to a device owned by the same workspace.
pub async fn scan_on_device_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<ExecutionContext>,
    Json(req): Json<DeviceScanRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let org_id = ctx.organization_id.filter(|_| !ctx.is_guest()).ok_or((
        StatusCode::FORBIDDEN,
        "Sign in to run a check on a connected device.".into(),
    ))?;
    let domain = mailent_scanner::normalize_scan_domain(&req.domain)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let device = state
        .devices
        .find_device_by_id(req.device_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .filter(|device| device.organization_id == org_id && device.is_active())
        .ok_or((
            StatusCode::NOT_FOUND,
            "Device not found in this workspace.".into(),
        ))?;
    if !device.agent_enabled
        || !device
            .capabilities
            .iter()
            .any(|cap| cap == "infrastructure_scan")
        || OffsetDateTime::now_utc() - device.last_seen_at > time::Duration::minutes(5)
    {
        return Err((
            StatusCode::CONFLICT,
            "Start 'mailent agent run' on this device, then try again.".into(),
        ));
    }
    if state
        .jobs
        .count_active_for_agent(device.id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        >= 5
    {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "This device already has five checks queued. Wait for one to finish.".into(),
        ));
    }
    let job =
        AgentJob::new_infrastructure_assessment(org_id, domain, 120, Some(device.id), None, None);
    state
        .jobs
        .create_job(&job)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok((StatusCode::ACCEPTED, Json(job)))
}

pub async fn get_scan_job_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<ExecutionContext>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let org_id = ctx.organization_id.filter(|_| !ctx.is_guest()).ok_or((
        StatusCode::FORBIDDEN,
        "Sign in to view device checks.".into(),
    ))?;
    let job = state
        .jobs
        .find_by_id(id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .filter(|job| job.organization_id == org_id)
        .ok_or((StatusCode::NOT_FOUND, "Check not found.".into()))?;
    Ok(Json(job))
}
