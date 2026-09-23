use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use mailent_domain::SensorHeartbeat;
use mailent_storage::StorageError;

use crate::state::AppState;

pub async fn record_heartbeat_handler(
    State(state): State<AppState>,
    Json(heartbeat): Json<SensorHeartbeat>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    state
        .sensors
        .record_heartbeat(heartbeat)
        .await
        .map_err(storage_error)?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_sensors_handler(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let sensors = state.sensors.list_sensors().await.map_err(storage_error)?;
    Ok(Json(sensors))
}

fn storage_error(error: StorageError) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}
