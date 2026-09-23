use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use mailent_storage::StorageError;
use serde::Deserialize;
use uuid::Uuid;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ListAnomaliesQuery {
    pub limit: Option<usize>,
}

fn storage_error(err: StorageError) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

pub async fn get_asset_baseline_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let baseline = state
        .baselines
        .get_baseline(id)
        .await
        .map_err(storage_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("baseline for asset {id} not found"),
            )
        })?;

    Ok(Json(baseline))
}

pub async fn list_asset_anomalies_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(query): Query<ListAnomaliesQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let limit = query.limit.unwrap_or(100).min(500);
    let anomalies = state
        .baselines
        .list_anomalies(Some(id), limit)
        .await
        .map_err(storage_error)?;

    Ok(Json(anomalies))
}

pub async fn list_anomalies_handler(
    State(state): State<AppState>,
    Query(query): Query<ListAnomaliesQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let limit = query.limit.unwrap_or(100).min(500);
    let anomalies = state
        .baselines
        .list_anomalies(None, limit)
        .await
        .map_err(storage_error)?;

    Ok(Json(anomalies))
}
