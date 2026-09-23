use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use mailent_domain::{AnalystLabel, AnalystOutcome, PriorityLevel};
use mailent_storage::StorageError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ListTrainingRecordsQuery {
    pub limit: Option<usize>,
    pub investigation_id: Option<Uuid>,
    pub asset_id: Option<Uuid>,
    pub unlabeled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct TrainingRecordResponse {
    pub id: Uuid,
    pub investigation_id: Uuid,
    pub asset_id: Uuid,
    pub feature_schema_version: u32,
    pub captured_at: String,
    pub automated_label: Option<serde_json::Value>,
    pub analyst_label: Option<serde_json::Value>,
    pub labeled_at: Option<String>,
    pub features: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct AttachAnalystLabelRequest {
    pub outcome: AnalystOutcome,
    pub label_source: Option<String>,
    pub priority: Option<PriorityLevel>,
    pub note: Option<String>,
    pub labeled_by: Option<String>,
}

fn storage_error(err: StorageError) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

fn to_response(record: &mailent_domain::TrainingRecord) -> TrainingRecordResponse {
    TrainingRecordResponse {
        id: record.id,
        investigation_id: record.investigation_id,
        asset_id: record.asset_id,
        feature_schema_version: record.feature_schema_version,
        captured_at: record.captured_at.to_string(),
        automated_label: record
            .automated_label
            .as_ref()
            .and_then(|l| serde_json::to_value(l).ok()),
        analyst_label: record
            .analyst_label
            .as_ref()
            .and_then(|l| serde_json::to_value(l).ok()),
        labeled_at: record.labeled_at.map(|t| t.to_string()),
        features: serde_json::to_value(&record.features).unwrap_or_default(),
    }
}

pub async fn list_training_records_handler(
    State(state): State<AppState>,
    Query(query): Query<ListTrainingRecordsQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let limit = query.limit.unwrap_or(100).min(500);
    let records = if query.unlabeled == Some(true) {
        state
            .training
            .list_unlabeled(limit)
            .await
            .map_err(storage_error)?
    } else {
        state
            .training
            .list_recent(query.investigation_id, query.asset_id, limit)
            .await
            .map_err(storage_error)?
    };
    Ok(Json(records.iter().map(to_response).collect::<Vec<_>>()))
}

pub async fn get_training_record_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let record = state
        .training
        .find_by_id(id)
        .await
        .map_err(storage_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("training record {id} not found"),
            )
        })?;
    Ok(Json(to_response(&record)))
}

pub async fn attach_analyst_label_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<AttachAnalystLabelRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let label = AnalystLabel {
        outcome: payload.outcome,
        priority: payload.priority,
        label_source: payload
            .label_source
            .unwrap_or_else(|| "analyst".to_string()),
        note: payload.note,
        labeled_by: payload.labeled_by,
    };
    state
        .training
        .attach_analyst_label(id, &label)
        .await
        .map_err(storage_error)?;
    let record = state
        .training
        .find_by_id(id)
        .await
        .map_err(storage_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("training record {id} not found"),
            )
        })?;
    Ok(Json(to_response(&record)))
}

/// Simple JSONL export path for offline use.  One record per line, NDJSON.
pub async fn export_training_records_handler(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let records = state
        .training
        .list_recent(None, None, 100_000)
        .await
        .map_err(storage_error)?;
    let mut body = String::new();
    for record in records {
        if let Ok(line) = serde_json::to_string(&record) {
            body.push_str(&line);
            body.push('\n');
        }
    }
    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/x-ndjson")],
        body,
    ))
}
