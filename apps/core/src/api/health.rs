use crate::AppState;
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::json;

pub async fn health_handler() -> impl IntoResponse {
    Json(json!({"status": "ok", "service": "mailent-core", "version": env!("CARGO_PKG_VERSION")}))
}

pub async fn ready_handler(State(state): State<AppState>) -> impl IntoResponse {
    let ready = state.policy_pack.validate().is_ok();
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(json!({
            "ready": ready, "policy_loaded": ready, "service": "mailent-core",
            "policy_name": state.policy_pack.name, "policy_version": state.policy_pack.version,
            "rule_count": state.policy_pack.rules.len(), "storage": state.storage_mode, "decision_provider": state.decision_provider_name
        })),
    )
}
