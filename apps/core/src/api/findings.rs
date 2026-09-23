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
pub struct ListFindingsQuery {
    pub session_id: Option<Uuid>,
}

pub async fn list_findings_handler(
    State(state): State<AppState>,
    Query(query): Query<ListFindingsQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let mut findings = state.findings.list_all().await.map_err(storage_error)?;

    if let Some(session_id) = query.session_id {
        findings.retain(|f| f.evidence.iter().any(|e| e.session_id == Some(session_id)));
    }

    Ok(Json(findings))
}

pub async fn get_finding_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let finding = state
        .findings
        .find_by_id(id)
        .await
        .map_err(storage_error)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("finding {id} not found")))?;

    Ok(Json(finding))
}

fn storage_error(error: StorageError) -> (StatusCode, String) {
    match error {
        StorageError::Conflict(message) => (StatusCode::CONFLICT, message),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage operation failed".into(),
        ),
    }
}
