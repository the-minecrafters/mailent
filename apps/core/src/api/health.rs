use crate::AppState;
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::json;

pub async fn health_handler() -> impl IntoResponse {
    Json(json!({"status": "ok", "service": "mailent-core", "version": env!("CARGO_PKG_VERSION")}))
}

/// A connection check only: no observation, finding, or decision is saved.
pub async fn check_decision_provider(State(state): State<AppState>) -> impl IntoResponse {
    let result = state
        .decision_provider
        .assess(mailent_domain::DecisionContext {
            session_id: uuid::Uuid::nil(),
            findings: vec![],
            metadata: json!({"purpose": "connection_check"}),
        })
        .await;
    let connected = result.is_ok_and(|result| result.provider_info.starts_with("jev:"));
    let message = if connected {
        "Jev responded successfully."
    } else if state.decision_provider_name == "disabled" {
        "Jev is not configured. Rule-based security checks are available."
    } else {
        "Jev (api.codiv.ai) is temporarily overloaded or unavailable. Rule-based security checks remain active with deterministic fallback."
    };
    Json(json!({"connected": connected, "message": message}))
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
