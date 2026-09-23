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
