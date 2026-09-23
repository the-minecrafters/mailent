use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use mailent_domain::InvestigationStatus;
use mailent_storage::StorageError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ListInvestigationsQuery {
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateInvestigationStatusRequest {
    pub status: InvestigationStatus,
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub success: bool,
    pub status: String,
}

fn storage_error(err: StorageError) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

pub async fn list_investigations_handler(
    State(state): State<AppState>,
    Query(query): Query<ListInvestigationsQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let limit = query.limit.unwrap_or(100).min(500);
    let investigations = state
        .investigations
        .list_all(limit)
        .await
        .map_err(storage_error)?;

    Ok(Json(investigations))
}

pub async fn get_investigation_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let investigation = state
        .investigations
        .find_by_id(id)
        .await
        .map_err(storage_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("investigation {id} not found"),
            )
        })?;

    #[derive(Serialize)]
    struct InvestigationContext {
        #[serde(flatten)]
        investigation: mailent_domain::Investigation,
        remediations: Vec<mailent_domain::RemediationRecord>,
    }
    let remediations = state
        .remediations
        .list_for_asset(investigation.asset_id)
        .await
        .map_err(storage_error)?
        .into_iter()
        .filter(|r| r.investigation_id == Some(id))
        .collect();
    Ok(Json(InvestigationContext {
        investigation,
        remediations,
    }))
}

pub async fn update_investigation_status_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateInvestigationStatusRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    state
        .investigations
        .update_status(id, payload.status)
        .await
        .map_err(storage_error)?;

    Ok(Json(StatusResponse {
        success: true,
        status: format!("{:?}", payload.status),
    }))
}

pub async fn list_decisions_handler(
    State(state): State<AppState>,
    Query(query): Query<ListInvestigationsQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let limit = query.limit.unwrap_or(100).min(500);
    let decisions = state
        .decisions
        .list_recent(limit)
        .await
        .map_err(storage_error)?;

    Ok(Json(decisions))
}
