use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use mailent_domain::ProbeRequest;
use mailent_storage::StorageError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ListProbesQuery {
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct ProbeAccepted {
    pub probe_id: Uuid,
    pub status: &'static str,
}

fn storage_error(err: StorageError) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

/// `POST /api/v1/assets/{id}/probe` — schedule an active probe for an asset.
///
/// Runs the probe asynchronously: returns immediately with `202 Accepted` and
/// a `probe_id`.  The result can be retrieved via `GET /api/v1/probes/{id}`.
pub async fn trigger_probe_handler(
    State(state): State<AppState>,
    Path(asset_id): Path<Uuid>,
    Json(req): Json<ProbeRequest>,
) -> Result<(StatusCode, Json<ProbeAccepted>), (StatusCode, String)> {
    let probe_id = crate::probes::schedule_probe(&state, asset_id, req).await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(ProbeAccepted {
            probe_id,
            status: "accepted",
        }),
    ))
}

/// `GET /api/v1/assets/{id}/probes` — list probe runs for an asset.
pub async fn list_probes_for_asset_handler(
    State(state): State<AppState>,
    Path(asset_id): Path<Uuid>,
    Query(query): Query<ListProbesQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let limit = query.limit.unwrap_or(20).min(100);
    let runs = state
        .probes
        .list_for_asset(asset_id, limit)
        .await
        .map_err(storage_error)?;
    Ok(Json(runs))
}

/// `GET /api/v1/probes/{id}` — get a single probe run by ID.
pub async fn get_probe_handler(
    State(state): State<AppState>,
    Path(probe_id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let run = state
        .probes
        .find_by_id(probe_id)
        .await
        .map_err(storage_error)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("probe {probe_id} not found")))?;
    Ok(Json(run))
}

/// `GET /api/v1/probes` — list recent probe runs across all assets.
pub async fn list_recent_probes_handler(
    State(state): State<AppState>,
    Query(query): Query<ListProbesQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let limit = query.limit.unwrap_or(50).min(200);
    let runs = state
        .probes
        .list_recent(limit)
        .await
        .map_err(storage_error)?;
    Ok(Json(runs))
}
