use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use mailent_domain::{
    IntegrationConfig, IntegrationEventPayload, IntegrationEventType, UpsertIntegrationRequest,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{integrations::dispatch_to_destination, state::AppState};

fn storage_error(error: mailent_storage::StorageError) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

pub async fn list_integrations_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<IntegrationConfig>>, (StatusCode, String)> {
    let list = state.integrations.list_all().await.map_err(storage_error)?;
    Ok(Json(list))
}

pub async fn create_integration_handler(
    State(state): State<AppState>,
    Json(req): Json<UpsertIntegrationRequest>,
) -> Result<(StatusCode, Json<IntegrationConfig>), (StatusCode, String)> {
    if req.name.trim().is_empty() || req.destination.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Name and destination must not be empty".into(),
        ));
    }

    let now = OffsetDateTime::now_utc();
    let config = IntegrationConfig {
        id: Uuid::new_v4(),
        name: req.name.trim().to_string(),
        kind: req.kind,
        destination: req.destination.trim().to_string(),
        event_types: req.event_types,
        enabled: req.enabled,
        auth_header: req.auth_header,
        last_delivery_at: None,
        last_status_code: None,
        last_error: None,
        created_at: now,
        updated_at: now,
    };

    state
        .integrations
        .save(&config)
        .await
        .map_err(storage_error)?;
    Ok((StatusCode::CREATED, Json(config)))
}

pub async fn get_integration_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<IntegrationConfig>, (StatusCode, String)> {
    let config = state
        .integrations
        .find_by_id(id)
        .await
        .map_err(storage_error)?
        .ok_or((StatusCode::NOT_FOUND, "Integration not found".into()))?;
    Ok(Json(config))
}

pub async fn update_integration_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpsertIntegrationRequest>,
) -> Result<Json<IntegrationConfig>, (StatusCode, String)> {
    let mut config = state
        .integrations
        .find_by_id(id)
        .await
        .map_err(storage_error)?
        .ok_or((StatusCode::NOT_FOUND, "Integration not found".into()))?;

    if req.name.trim().is_empty() || req.destination.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Name and destination must not be empty".into(),
        ));
    }

    config.name = req.name.trim().to_string();
    config.kind = req.kind;
    config.destination = req.destination.trim().to_string();
    config.event_types = req.event_types;
    config.enabled = req.enabled;
    config.auth_header = req.auth_header;
    config.updated_at = OffsetDateTime::now_utc();

    state
        .integrations
        .save(&config)
        .await
        .map_err(storage_error)?;
    Ok(Json(config))
}

pub async fn delete_integration_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let deleted = state.integrations.delete(id).await.map_err(storage_error)?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::NOT_FOUND, "Integration not found".into()))
    }
}

pub async fn test_integration_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let config = state
        .integrations
        .find_by_id(id)
        .await
        .map_err(storage_error)?
        .ok_or((StatusCode::NOT_FOUND, "Integration not found".into()))?;

    let test_payload = IntegrationEventPayload {
        event_id: Uuid::new_v4(),
        event_type: IntegrationEventType::VerificationCompleted,
        title: "Test Integration Event".into(),
        summary: format!(
            "Mailent integration verification test for '{}'",
            config.name
        ),
        asset_id: None,
        asset_name: Some("test.mailent.local".into()),
        investigation_id: None,
        finding_id: None,
        probe_id: None,
        details: serde_json::json!({
            "test": true,
            "integration_id": config.id,
            "integration_name": config.name,
        }),
        timestamp: OffsetDateTime::now_utc(),
    };

    match dispatch_to_destination(&state, &config, &test_payload).await {
        Ok(status) => Ok(Json(serde_json::json!({
            "success": true,
            "status_code": status,
            "message": "Integration test delivered successfully",
        }))),
        Err(err) => Err((
            StatusCode::BAD_GATEWAY,
            format!("Integration test failed: {err}"),
        )),
    }
}
