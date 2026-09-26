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
            "rule_count": state.policy_pack.rules.len(), "storage": state.storage_mode, "decision_provider": state.decision_provider_name,
            "blocked_mail_ports": mailent_scanner::blocked_mail_ports()
        })),
    )
}

pub async fn reset_database_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = headers
        .get("x-mailent-admin-token")
        .and_then(|v| v.to_str().ok());
    if token != Some("mailent_demo_wipe_2026") {
        return Err((StatusCode::UNAUTHORIZED, "Invalid admin token".into()));
    }
    state.mem_storage.reset_all_data().await;
    if let Some(ref pg) = state.pg_storage {
        pg.reset_all_data()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    tracing::info!("Reset all workspace data successfully");
    Ok(Json(json!({
        "status": "ok",
        "message": "All workspace and telemetry data reset successfully"
    })))
}

