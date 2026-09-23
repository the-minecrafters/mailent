use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use mailent_storage::StorageError;

use crate::state::AppState;

pub async fn list_certificates_handler(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let certs = state.certificates.list_all().await.map_err(storage_error)?;

    Ok(Json(certs))
}

pub async fn get_certificate_handler(
    State(state): State<AppState>,
    Path(fingerprint): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let cert = state
        .certificates
        .find_by_fingerprint(&fingerprint)
        .await
        .map_err(storage_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("certificate {fingerprint} not found"),
            )
        })?;

    Ok(Json(cert))
}

fn storage_error(error: StorageError) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}
