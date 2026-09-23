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
pub struct ListDriftQuery {
    pub limit: Option<usize>,
}

pub async fn list_assets_handler(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let mut assets = state.assets.list_all().await.map_err(storage_error)?;
    let mut response = Vec::with_capacity(assets.len());
    for asset in &mut assets {
        asset.active_findings_count = state
            .findings
            .list_for_asset(asset.id)
            .await
            .map_err(storage_error)?
            .len();
        let authorized =
            crate::probes::authorized_asset_target(asset, &state.probe_config.to_scope()).is_some();
        let mut value = serde_json::to_value(&*asset)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        value["probe_authorized"] = serde_json::json!(authorized);
        response.push(value);
    }
    Ok(Json(response))
}

pub async fn get_asset_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let asset = state
        .assets
        .find_by_id(id)
        .await
        .map_err(storage_error)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("asset {id} not found")))?;

    let authorized_target =
        crate::probes::authorized_asset_target(&asset, &state.probe_config.to_scope());
    let authorized = authorized_target.is_some();
    let drift_events = state
        .assets
        .list_drift_events(Some(id), 20)
        .await
        .map_err(storage_error)?;
    let probes = state
        .probes
        .list_for_asset(id, 20)
        .await
        .map_err(storage_error)?;
    let active = probes.iter().find(|p| p.finished_at.is_some()).cloned();
    let verification_state = mailent_domain::probe::AssetVerificationState::evaluate(
        id,
        authorized_target,
        &probes,
        &drift_events,
        time::OffsetDateTime::now_utc(),
    );

    let mut response = serde_json::to_value(asset)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    response["probe_authorized"] = serde_json::json!(authorized);
    response["active_verification"] = serde_json::to_value(active)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    response["verification_state"] = serde_json::to_value(verification_state)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(response))
}

pub async fn list_asset_drift_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(query): Query<ListDriftQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let limit = query.limit.unwrap_or(100).min(500);
    let events = state
        .assets
        .list_drift_events(Some(id), limit)
        .await
        .map_err(storage_error)?;

    Ok(Json(events))
}

pub async fn list_drift_events_handler(
    State(state): State<AppState>,
    Query(query): Query<ListDriftQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let limit = query.limit.unwrap_or(100).min(500);
    let events = state
        .assets
        .list_drift_events(None, limit)
        .await
        .map_err(storage_error)?;

    Ok(Json(events))
}

pub async fn list_asset_certificates_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let certs = state
        .certificates
        .list_for_asset(id)
        .await
        .map_err(storage_error)?;

    Ok(Json(certs))
}

pub async fn list_asset_sessions_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(query): Query<ListDriftQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let asset = state
        .assets
        .find_by_id(id)
        .await
        .map_err(storage_error)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("asset {id} not found")))?;

    let limit = query.limit.unwrap_or(100).min(500);
    let mut all_sessions = Vec::new();

    for addr in &asset.addresses {
        let sessions = state
            .sessions
            .list_for_asset(addr, limit)
            .await
            .map_err(storage_error)?;
        all_sessions.extend(sessions);
    }

    all_sessions.sort_by_key(|a| std::cmp::Reverse(a.last_seen));
    all_sessions.dedup_by(|a, b| a.session_id == b.session_id);
    all_sessions.truncate(limit);

    Ok(Json(all_sessions))
}

pub async fn list_asset_findings_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let evidence = crate::evidence::EvidenceSnapshot::asset(&state, id)
        .await
        .map_err(storage_error)?
        .ok_or((StatusCode::NOT_FOUND, "asset not found".into()))?;
    Ok(Json(evidence.findings))
}

pub async fn get_asset_intelligence_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let asset = state
        .assets
        .find_by_id(id)
        .await
        .map_err(storage_error)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("asset {id} not found")))?;

    let domain = asset
        .primary_name
        .clone()
        .or_else(|| asset.hostnames.first().cloned())
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("asset {id} does not have associated domain names"),
            )
        })?;

    crate::api::intelligence::get_domain_intelligence_handler(State(state), Path(domain)).await
}

pub async fn get_asset_verification_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let asset = state
        .assets
        .find_by_id(id)
        .await
        .map_err(storage_error)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("asset {id} not found")))?;

    let probes = state
        .probes
        .list_for_asset(id, 50)
        .await
        .map_err(storage_error)?;

    let drift_events = state
        .assets
        .list_drift_events(Some(id), 50)
        .await
        .map_err(storage_error)?;

    let authorized_target =
        crate::probes::authorized_asset_target(&asset, &state.probe_config.to_scope());

    let verification = mailent_domain::probe::AssetVerificationState::evaluate(
        id,
        authorized_target,
        &probes,
        &drift_events,
        time::OffsetDateTime::now_utc(),
    );

    Ok(Json(verification))
}

fn storage_error(error: StorageError) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}
