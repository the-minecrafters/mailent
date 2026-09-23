use crate::{evidence::EvidenceSnapshot, state::AppState};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use mailent_domain::{PostureSubjectKind, RemediationGuidance, SecurityPosture};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct AssetPostureResponse {
    pub posture: SecurityPosture,
    pub guidance: Vec<RemediationGuidance>,
    pub remediations: Vec<mailent_domain::RemediationRecord>,
    pub asset_id: Option<Uuid>,
    pub verification_conditions:
        std::collections::BTreeMap<Uuid, mailent_domain::RemediationCondition>,
}
async fn posture(
    state: &AppState,
    id: Uuid,
    kind: PostureSubjectKind,
) -> Result<Json<AssetPostureResponse>, (StatusCode, String)> {
    let snapshot = match kind {
        PostureSubjectKind::Asset => EvidenceSnapshot::asset(state, id).await,
        PostureSubjectKind::Session => EvidenceSnapshot::session(state, id).await,
        PostureSubjectKind::Investigation => EvidenceSnapshot::investigation(state, id).await,
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::NOT_FOUND, format!("subject {id} not found")))?;
    let (posture, guidance) = snapshot.posture(kind, id);
    let verification_conditions = guidance
        .iter()
        .filter_map(|g| mailent_domain::RemediationCondition::for_guidance(g).map(|c| (g.id, c)))
        .collect();
    Ok(Json(AssetPostureResponse {
        posture,
        guidance,
        remediations: snapshot.remediations,
        asset_id: snapshot.asset.map(|a| a.id),
        verification_conditions,
    }))
}
pub async fn get_asset_posture_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AssetPostureResponse>, (StatusCode, String)> {
    posture(&state, id, PostureSubjectKind::Asset).await
}
pub async fn get_session_posture_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AssetPostureResponse>, (StatusCode, String)> {
    posture(&state, id, PostureSubjectKind::Session).await
}
pub async fn get_investigation_posture_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AssetPostureResponse>, (StatusCode, String)> {
    posture(&state, id, PostureSubjectKind::Investigation).await
}
