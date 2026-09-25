use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
};
use mailent_domain::{Finding, FindingCandidate, NormalizedObservation};
use mailent_storage::StorageError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{pipeline::process_observation_scoped, state::AppState};

#[derive(Debug, Serialize, Deserialize)]
pub struct EvaluateResponse {
    pub session_id: Uuid,
    pub observation: NormalizedObservation,
    pub candidate_count: usize,
    pub candidates: Vec<FindingCandidate>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitObservationResponse {
    pub session_id: Uuid,
    pub asset_id: Uuid,
    pub findings_count: usize,
    pub findings: Vec<Finding>,
}

pub async fn evaluate_observation_handler(
    State(state): State<AppState>,
    ctx: Option<Extension<crate::auth::ExecutionContext>>,
    Json(observation): Json<NormalizedObservation>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let org_id = ctx.as_ref().and_then(|Extension(c)| c.organization_id);
    let observation = scope_observation(observation, org_id);
    observation
        .validate()
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    tracing::info!(
        observation_id = %observation.observation_id,
        sensor_id = %observation.sensor_id,
        flow = %observation.flow,
        "Received observation for evaluation"
    );

    let obs_clone = observation.clone();
    let res = process_observation_scoped(&state, observation, org_id)
        .await
        .map_err(storage_error)?;

    let response = EvaluateResponse {
        session_id: res.session_id,
        observation: obs_clone,
        candidate_count: res.candidates.len(),
        candidates: res.candidates,
        findings: res.findings,
    };

    Ok((StatusCode::OK, Json(response)))
}

pub async fn submit_observation_handler(
    State(state): State<AppState>,
    ctx: Option<Extension<crate::auth::ExecutionContext>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json");

    let observation: NormalizedObservation = if content_type.contains("protobuf") {
        mailent_events::wire::decode(&body).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid protobuf payload: {e}"),
            )
        })?
    } else {
        serde_json::from_slice(&body).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid JSON payload: {e}"),
            )
        })?
    };

    let org_id = ctx.as_ref().and_then(|Extension(c)| c.organization_id);
    let observation = scope_observation(observation, org_id);
    observation
        .validate()
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;

    tracing::info!(
        observation_id = %observation.observation_id,
        sensor_id = %observation.sensor_id,
        flow = %observation.flow,
        "Received observation for submission"
    );

    let res = process_observation_scoped(&state, observation, org_id)
        .await
        .map_err(storage_error)?;

    let response = SubmitObservationResponse {
        session_id: res.session_id,
        asset_id: res.asset_id,
        findings_count: res.findings.len(),
        findings: res.findings,
    };

    Ok((StatusCode::OK, Json(response)))
}

fn storage_error(error: StorageError) -> (StatusCode, String) {
    match error {
        StorageError::Conflict(message) => (StatusCode::CONFLICT, message),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage operation failed: {error}"),
        ),
    }
}

fn scope_observation(
    mut observation: NormalizedObservation,
    org_id: Option<Uuid>,
) -> NormalizedObservation {
    if let Some(org) = org_id {
        observation.observation_id = Uuid::new_v5(&org, observation.observation_id.as_bytes());
        observation.sensor_id = format!("{org}:{}", observation.sensor_id);
    }
    observation
}
