use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use mailent_domain::AgentJob;
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{auth::ExecutionContext, state::AppState};

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
    if !super::devices::installation_online(&device, OffsetDateTime::now_utc()) {
        return Err((StatusCode::CONFLICT, "This CLI installation is offline. Run mailent agent run on that machine to accept remote scans.".into()));
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
    let mut job = state
        .jobs
        .find_by_id(id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .filter(|job| job.organization_id == org_id)
        .ok_or((StatusCode::NOT_FOUND, "Check not found.".into()))?;
    if job.state == mailent_domain::JobState::Pending
        && OffsetDateTime::now_utc() - job.created_at > time::Duration::seconds(60)
    {
        job.state = mailent_domain::JobState::Canceled;
        job.completed_at = Some(OffsetDateTime::now_utc());
        job.last_error =
            Some("Installation did not accept the scan while online. Start a new scan.".into());
        state
            .jobs
            .update_job(&job)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    Ok(Json(job))
}
