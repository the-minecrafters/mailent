use crate::{remediation, state::AppState};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use mailent_domain::RemediationRecord;
use serde::Deserialize;
use uuid::Uuid;
#[derive(Deserialize)]
pub struct StartRequest {
    pub finding_id: Uuid,
    pub session_id: Option<Uuid>,
    pub investigation_id: Option<Uuid>,
}
#[derive(Deserialize)]
pub struct AppliedRequest {
    pub note: Option<String>,
}
#[derive(Deserialize)]
pub struct VerifyRequest {
    pub request_id: Uuid,
}
type Error = (StatusCode, String);
pub async fn start(
    State(state): State<AppState>,
    Path(asset_id): Path<Uuid>,
    Json(req): Json<StartRequest>,
) -> Result<Json<RemediationRecord>, Error> {
    Ok(Json(
        remediation::start(
            &state,
            asset_id,
            req.finding_id,
            req.session_id,
            req.investigation_id,
        )
        .await?,
    ))
}
pub async fn list(
    State(state): State<AppState>,
    Path(asset_id): Path<Uuid>,
) -> Result<Json<Vec<RemediationRecord>>, Error> {
    Ok(Json(
        state
            .remediations
            .list_for_asset(asset_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
    ))
}
pub async fn get(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<RemediationRecord>, Error> {
    Ok(Json(remediation::get(&state, id).await?))
}
pub async fn applied(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<AppliedRequest>,
) -> Result<Json<RemediationRecord>, Error> {
    Ok(Json(remediation::mark_applied(&state, id, req.note).await?))
}
pub async fn verify(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<VerifyRequest>,
) -> Result<(StatusCode, Json<RemediationRecord>), Error> {
    Ok((
        StatusCode::ACCEPTED,
        Json(remediation::request_verification(&state, id, req.request_id).await?),
    ))
}

#[derive(Deserialize)]
pub struct SyncRemediationRequest {
    pub client_sync_id: Uuid,
    pub record: RemediationRecord,
    pub probe: Option<mailent_domain::ProbeRun>,
    pub device_note: Option<String>,
}

#[derive(serde::Serialize)]
pub struct SyncRemediationResponse {
    pub synced: bool,
    pub remediation_id: Uuid,
    pub state: mailent_domain::RemediationState,
}

pub async fn sync(
    State(state): State<AppState>,
    Json(req): Json<SyncRemediationRequest>,
) -> Result<Json<SyncRemediationResponse>, Error> {
    let storage_error =
        |e: mailent_storage::StorageError| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string());

    let _ = state.findings.save(req.record.finding.clone()).await;

    let record = req.record;
    if let Some(existing) = state
        .remediations
        .find_by_id(record.id)
        .await
        .map_err(storage_error)?
    {
        let _ = state
            .remediations
            .update(&record, existing.revision)
            .await
            .map_err(storage_error)?;
    } else {
        let _ = state
            .remediations
            .create(&record)
            .await
            .map_err(storage_error)?;
    }

    if let Some(ref probe) = req.probe {
        let _ = state.probes.reserve(probe, 0).await;
        let _ = state.probes.update(probe).await;
    }

    if record.state == mailent_domain::RemediationState::VerifiedFixed {
        crate::integrations::notify_event(
            &state,
            crate::integrations::EventNotification::new(
                mailent_domain::IntegrationEventType::RemediationVerified,
                format!("Remediation Verified: {}", record.finding.title),
                format!("Remediation verified fixed for asset {}", record.asset_id),
            )
            .with_asset(record.asset_id, None)
            .with_finding(record.finding.id)
            .with_details(serde_json::to_value(&record).unwrap_or_default()),
        );
    }

    Ok(Json(SyncRemediationResponse {
        synced: true,
        remediation_id: record.id,
        state: record.state,
    }))
}
