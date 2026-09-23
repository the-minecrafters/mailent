use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use mailent_domain::{
    AgentJob, DriftEvent, InfrastructureMonitor, MonitorCadence, MonitorExecutionTarget,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{auth::ExecutionContext, state::AppState};

#[derive(Debug, Deserialize)]
pub struct CreateMonitorRequest {
    pub domain: String,
    pub cadence: MonitorCadence,
    pub target: MonitorExecutionTarget,
    pub notify_on_drift: Option<bool>,
    pub notify_on_regression: Option<bool>,
    pub auto_investigate: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct DomainHistoryEntry {
    pub assessment_id: Uuid,
    pub created_at: String,
    pub posture_score: f32,
    pub posture_grade: String,
    pub protocols_identified: Vec<String>,
    pub findings_count: usize,
    pub drift_events: Vec<DriftEvent>,
    pub security_regressions: Vec<DriftEvent>,
}

#[derive(Debug, Serialize)]
pub struct DomainHistoryResponse {
    pub domain: String,
    pub monitor: Option<InfrastructureMonitor>,
    pub history: Vec<DomainHistoryEntry>,
}

pub async fn list_monitors_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<ExecutionContext>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let org_id = ctx
        .organization_id
        .unwrap_or(mailent_domain::DEFAULT_ORG_ID);
    let monitors = state
        .monitors
        .list_for_org(org_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(monitors))
}

pub async fn create_monitor_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<ExecutionContext>,
    Json(req): Json<CreateMonitorRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let org_id = ctx
        .organization_id
        .unwrap_or(mailent_domain::DEFAULT_ORG_ID);
    let domain = req.domain.trim().to_lowercase();
    if domain.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Domain cannot be empty".to_string(),
        ));
    }

    let monitor = InfrastructureMonitor::new(
        org_id,
        domain,
        req.target,
        req.cadence,
        true, // Start immediately on creation
    );

    state
        .monitors
        .save(&monitor)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok((StatusCode::CREATED, Json(monitor)))
}

pub async fn get_monitor_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<ExecutionContext>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let org_id = ctx
        .organization_id
        .unwrap_or(mailent_domain::DEFAULT_ORG_ID);
    let monitor = state
        .monitors
        .find_by_id(id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Monitor not found".to_string()))?;

    if monitor.organization_id != org_id {
        return Err((
            StatusCode::FORBIDDEN,
            "Monitor belongs to another organization".to_string(),
        ));
    }

    Ok(Json(monitor))
}

pub async fn run_now_monitor_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<ExecutionContext>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let org_id = ctx
        .organization_id
        .unwrap_or(mailent_domain::DEFAULT_ORG_ID);
    let mut monitor = state
        .monitors
        .find_by_id(id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Monitor not found".to_string()))?;

    if monitor.organization_id != org_id {
        return Err((
            StatusCode::FORBIDDEN,
            "Monitor belongs to another organization".to_string(),
        ));
    }

    let now = OffsetDateTime::now_utc();
    monitor.next_run_at = now;
    monitor.updated_at = now;
    state
        .monitors
        .save(&monitor)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let target_agent_id = match monitor.execution_target {
        MonitorExecutionTarget::Cloud => None,
        MonitorExecutionTarget::Agent(dev_id) => Some(dev_id),
    };

    let job = AgentJob::new_infrastructure_assessment(
        org_id,
        monitor.domain.clone(),
        120,
        target_agent_id,
        Some(format!(
            "manual-run-{}-{}",
            monitor.id,
            now.unix_timestamp()
        )),
        Some(monitor.id),
    );

    let _ = state.jobs.create_job(&job).await;

    Ok(Json(serde_json::json!({
        "status": "queued",
        "job_id": job.id,
        "monitor_id": monitor.id,
    })))
}

pub async fn delete_monitor_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<ExecutionContext>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let org_id = ctx
        .organization_id
        .unwrap_or(mailent_domain::DEFAULT_ORG_ID);
    let monitor = state
        .monitors
        .find_by_id(id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Monitor not found".to_string()))?;

    if monitor.organization_id != org_id {
        return Err((
            StatusCode::FORBIDDEN,
            "Monitor belongs to another organization".to_string(),
        ));
    }

    state
        .monitors
        .delete(id, org_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({ "deleted": true })))
}

pub async fn get_domain_history_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<ExecutionContext>,
    Path(domain): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let org_id = ctx
        .organization_id
        .unwrap_or(mailent_domain::DEFAULT_ORG_ID);
    let domain = domain.trim().to_lowercase();

    // Find monitor if any
    let monitors = state
        .monitors
        .list_for_org(org_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let monitor = monitors
        .into_iter()
        .find(|m| m.domain.to_lowercase() == domain);

    // List all assessments for this org
    let summaries = state
        .assessments
        .list_for_org(org_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut domain_summaries: Vec<_> = summaries
        .into_iter()
        .filter(|s| s.source_type == "infrastructure" && s.target.to_lowercase() == domain)
        .collect();

    // Sort ascending by time for drift calculation
    domain_summaries.sort_by_key(|s| s.created_at);

    let mut history_entries = Vec::new();
    let mut prev_assessment: Option<mailent_domain::AssessmentRecord> = None;
    let mut prev_findings: Vec<mailent_domain::Finding> = Vec::new();

    for summary in domain_summaries {
        if let Ok(Some(current_record)) = state
            .assessments
            .find_by_id_scoped(summary.id, org_id)
            .await
        {
            let mut current_findings = Vec::new();
            for fid in &current_record.finding_ids {
                if let Ok(Some(f)) = state.findings.find_by_id(*fid).await {
                    current_findings.push(f);
                }
            }

            let (drift_events, security_regressions) = if let Some(ref prev_rec) = prev_assessment {
                let drifts =
                    mailent_correlation::drift::InfrastructureDriftCorrelator::compare_assessments(
                        prev_rec,
                        &current_record,
                        &prev_findings,
                        &current_findings,
                    );
                let regs = mailent_correlation::drift::InfrastructureDriftCorrelator::extract_security_regressions(&drifts, &current_findings)
                    .into_iter()
                    .cloned()
                    .collect::<Vec<_>>();
                (drifts, regs)
            } else {
                (Vec::new(), Vec::new())
            };

            let entry = DomainHistoryEntry {
                assessment_id: current_record.id,
                created_at: current_record
                    .created_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
                posture_score: current_record.posture_score,
                posture_grade: current_record.posture_grade.clone(),
                protocols_identified: current_record.protocols_identified.clone(),
                findings_count: current_findings.len(),
                drift_events,
                security_regressions,
            };

            history_entries.push(entry);

            prev_assessment = Some(current_record);
            prev_findings = current_findings;
        }
    }

    // Reverse history entries so most recent is first
    history_entries.reverse();

    Ok(Json(DomainHistoryResponse {
        domain,
        monitor,
        history: history_entries,
    }))
}
