use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use mailent_domain::{
    AssessmentRecord, Asset, DriftEvent, EmailSession, Finding, IntegrationEventType,
    Investigation, InvestigationStatus, JobExecutionTarget, JobState,
};
use serde::Deserialize;
use time::OffsetDateTime;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::{
    auth::{Actor, ExecutionContext},
    integrations::{EventNotification, notify_event},
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct AgentHeartbeatRequest {
    pub version: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CompleteJobRequest {
    pub assessment: Option<AssessmentRecord>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub assets: Vec<Asset>,
    #[serde(default)]
    pub sessions: Vec<EmailSession>,
    #[serde(default)]
    pub output_summary: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct FailJobRequest {
    pub error: String,
}

fn require_device_actor(ctx: &ExecutionContext) -> Result<(Uuid, Uuid), (StatusCode, String)> {
    match ctx.actor {
        Actor::Device {
            device_id,
            organization_id,
            ..
        } => Ok((device_id, organization_id)),
        _ => Err((
            StatusCode::FORBIDDEN,
            "Endpoint requires a registered device agent token".to_string(),
        )),
    }
}

pub async fn agent_heartbeat_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<ExecutionContext>,
    Json(req): Json<AgentHeartbeatRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (device_id, _org_id) = require_device_actor(&ctx)?;

    let status = req.status.unwrap_or_else(|| "online".to_string());
    state
        .devices
        .heartbeat(
            device_id,
            req.version,
            req.capabilities,
            status,
            OffsetDateTime::now_utc(),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "device_id": device_id,
        "server_time": OffsetDateTime::now_utc().to_string(),
    })))
}

pub async fn agent_poll_jobs_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<ExecutionContext>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (device_id, org_id) = require_device_actor(&ctx)?;
    let now = OffsetDateTime::now_utc();

    // Lease next job for 300 seconds (5 minutes)
    let job_opt = state
        .jobs
        .lease_next_job(device_id, org_id, now, 300)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if let Some(ref job) = job_opt {
        let _ = state
            .devices
            .update_agent_status(device_id, Some("busy".into()), Some(job.id), false)
            .await;
        info!(
            device_id = %device_id,
            job_id = %job.id,
            "Agent leased job successfully"
        );
    } else {
        let _ = state
            .devices
            .update_agent_status(device_id, Some("idle".into()), None, false)
            .await;
    }

    Ok(Json(serde_json::json!({
        "job": job_opt
    })))
}

pub async fn agent_complete_job_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<ExecutionContext>,
    Path(id): Path<Uuid>,
    Json(mut req): Json<CompleteJobRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (device_id, org_id) = require_device_actor(&ctx)?;

    let mut job = state
        .jobs
        .find_by_id(id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Job not found".to_string()))?;

    if job.organization_id != org_id {
        return Err((
            StatusCode::FORBIDDEN,
            "Job belongs to another organization".to_string(),
        ));
    }

    if let JobExecutionTarget::Agent(target_id) = job.execution_target {
        if target_id != device_id {
            return Err((
                StatusCode::FORBIDDEN,
                "Job is not assigned to this device".to_string(),
            ));
        }
    }

    let mut assessment_id = None;
    let now = OffsetDateTime::now_utc();

    if let Some(mut assessment) = req.assessment.take() {
        assessment = assessment.with_organization(org_id);
        assessment_id = Some(assessment.id);

        for finding in &mut req.findings {
            finding.organization_id = Some(org_id);
        }
        for asset in &mut req.assets {
            asset.organization_id = Some(org_id);
        }

        // Save assessment
        state
            .assessments
            .save(&assessment)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        for finding in &req.findings {
            let _ = state.findings.save(finding.clone()).await;
        }
        for asset in &req.assets {
            let _ = state.assets.upsert(asset.clone()).await;
        }
        for session in &req.sessions {
            let _ = state.sessions.save(session.clone()).await;
        }

        // Check for domain drift against prior infrastructure assessment
        if let Some(domain) = assessment.target_domain() {
            if let Ok(summaries) = state.assessments.list_for_org(org_id).await {
                let prior_summary = summaries
                    .into_iter()
                    .filter(|s| {
                        s.source_type == "infrastructure"
                            && s.target == domain
                            && s.id != assessment.id
                    })
                    .max_by_key(|s| s.created_at);

                if let Some(prior_s) = prior_summary {
                    if let Ok(Some(prior_rec)) = state
                        .assessments
                        .find_by_id_scoped(prior_s.id, org_id)
                        .await
                    {
                        // Gather prior findings
                        let mut prior_findings = Vec::new();
                        for fid in &prior_rec.finding_ids {
                            if let Ok(Some(f)) = state.findings.find_by_id(*fid).await {
                                prior_findings.push(f);
                            }
                        }

                        let drift_events = mailent_correlation::drift::InfrastructureDriftCorrelator::compare_assessments(
                            &prior_rec,
                            &assessment,
                            &prior_findings,
                            &req.findings,
                        );

                        let regressions = mailent_correlation::drift::InfrastructureDriftCorrelator::extract_security_regressions(&drift_events, &req.findings);

                        if !regressions.is_empty() {
                            info!(
                                domain = %domain,
                                regressions_count = regressions.len(),
                                "Security regressions detected in infrastructure monitor scan"
                            );
                            notify_event(
                                &state,
                                EventNotification::new(
                                    IntegrationEventType::SecurityRegressionDetected,
                                    format!("Security regression on {domain}"),
                                    format!(
                                        "Detected {} security regression(s) during scheduled scan.",
                                        regressions.len()
                                    ),
                                )
                                .with_details(serde_json::json!({
                                    "domain": domain,
                                    "regressions": regressions,
                                    "assessment_id": assessment.id,
                                })),
                            );
                        } else if !drift_events.is_empty() {
                            info!(
                                domain = %domain,
                                drift_count = drift_events.len(),
                                "Infrastructure drift detected in monitor scan"
                            );
                            notify_event(
                                &state,
                                EventNotification::new(
                                    IntegrationEventType::InfrastructureDriftDetected,
                                    format!("Infrastructure drift on {domain}"),
                                    format!(
                                        "Detected {} configuration change(s) during scheduled scan.",
                                        drift_events.len()
                                    ),
                                )
                                .with_details(serde_json::json!({
                                    "domain": domain,
                                    "drift_events": drift_events,
                                    "assessment_id": assessment.id,
                                })),
                            );
                        }

                        // Create or enrich investigation if meaningful security regressions exist
                        let _ = sync_infrastructure_investigation(
                            &state,
                            &assessment,
                            domain,
                            &drift_events,
                            &req.findings,
                            now,
                        )
                        .await;
                    }
                }
            }
        }

        // If this job was linked to a monitor, update the monitor
        if let Some(monitor_id) = job.monitor_id {
            if let Ok(Some(mut monitor)) = state.monitors.find_by_id(monitor_id).await {
                monitor.last_run_at = Some(now);
                monitor.last_success_at = Some(now);
                monitor.last_assessment_id = Some(assessment.id);
                monitor.next_run_at = monitor.cadence.next_run_after(now);
                monitor.updated_at = now;
                let _ = state.monitors.save(&monitor).await;
            }
        }
    }

    // Complete job
    job.state = JobState::Completed;
    job.completed_at = Some(now);
    job.result_assessment_id = assessment_id;
    state
        .jobs
        .update_job(&job)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Update device completed jobs and status
    let _ = state
        .devices
        .update_agent_status(device_id, Some("idle".into()), None, true)
        .await;

    Ok(Json(serde_json::json!({
        "status": "completed",
        "job_id": id,
        "assessment_id": assessment_id,
    })))
}

pub async fn agent_fail_job_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<ExecutionContext>,
    Path(id): Path<Uuid>,
    Json(req): Json<FailJobRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (device_id, org_id) = require_device_actor(&ctx)?;

    let mut job = state
        .jobs
        .find_by_id(id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Job not found".to_string()))?;

    if job.organization_id != org_id {
        return Err((
            StatusCode::FORBIDDEN,
            "Job belongs to another organization".to_string(),
        ));
    }

    if let JobExecutionTarget::Agent(target_id) = job.execution_target {
        if target_id != device_id {
            return Err((
                StatusCode::FORBIDDEN,
                "Job is not assigned to this device".to_string(),
            ));
        }
    }

    warn!(job_id = %id, error = %req.error, "Agent reported job failure");

    let now = OffsetDateTime::now_utc();
    job.state = JobState::Failed;
    job.completed_at = Some(now);
    job.last_error = Some(req.error.clone());

    state
        .jobs
        .update_job(&job)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let _ = state
        .devices
        .update_agent_status(device_id, Some("idle".into()), None, false)
        .await;

    if let Some(monitor_id) = job.monitor_id {
        if let Ok(Some(mut monitor)) = state.monitors.find_by_id(monitor_id).await {
            monitor.last_run_at = Some(now);
            monitor.last_failure_at = Some(now);
            monitor.last_error = Some(req.error);
            monitor.next_run_at = monitor.cadence.next_run_after(now);
            monitor.updated_at = now;
            let _ = state.monitors.save(&monitor).await;
        }
    }

    Ok(Json(serde_json::json!({
        "status": "failed",
        "job_id": id,
    })))
}

/// Coordinates infrastructure investigation creation and enrichment based on detected drift regressions.
/// Preserves continuity: enriches unresolved investigations without creating duplicate cases.
/// Benign drift (routine certificate renewal, MX additions, etc.) is preserved in history without opening cases.
pub async fn sync_infrastructure_investigation(
    state: &AppState,
    assessment: &AssessmentRecord,
    domain: &str,
    drift_events: &[DriftEvent],
    current_findings: &[Finding],
    now: OffsetDateTime,
) -> Result<Option<Investigation>, Box<dyn std::error::Error + Send + Sync>> {
    let regressions =
        mailent_correlation::drift::InfrastructureDriftCorrelator::extract_security_regressions(
            drift_events,
            current_findings,
        );

    let asset_id = assessment
        .asset_ids
        .first()
        .copied()
        .unwrap_or_else(|| Uuid::new_v5(&Uuid::NAMESPACE_OID, domain.as_bytes()));

    // Persist all drift events to asset storage for historical timeline
    for d in drift_events {
        let _ = state.assets.save_drift_event(d.clone()).await;
    }

    if regressions.is_empty() {
        debug!(
            domain = %domain,
            "No security regressions detected; benign drift recorded without investigation"
        );
        return Ok(None);
    }

    // Query existing investigations for this domain/asset
    let existing_list = state
        .investigations
        .list_for_asset(asset_id)
        .await
        .unwrap_or_default();
    let unresolved_opt = existing_list
        .iter()
        .find(|i| i.status != InvestigationStatus::Resolved);
    let is_new = unresolved_opt.is_none();

    let inv_opt = mailent_correlation::drift::InfrastructureDriftCorrelator::correlate_or_enrich_investigation(
        unresolved_opt,
        asset_id,
        domain,
        &regressions,
        current_findings,
        now,
    );

    if let Some(ref inv) = inv_opt {
        state
            .investigations
            .save(inv)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        if is_new {
            info!(
                domain = %domain,
                investigation_id = %inv.id,
                "Created new investigation for infrastructure security regression"
            );
            notify_event(
                state,
                EventNotification::new(
                    IntegrationEventType::InvestigationCreated,
                    format!("Investigation Created: {}", inv.title),
                    &inv.summary,
                )
                .with_asset(asset_id, Some(domain.to_string()))
                .with_investigation(inv.id)
                .with_details(serde_json::to_value(inv).unwrap_or_default()),
            );
        } else {
            info!(
                domain = %domain,
                investigation_id = %inv.id,
                "Enriched existing unresolved investigation with new regression signals"
            );
        }
    }

    Ok(inv_opt)
}
