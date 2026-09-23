use axum::{Json, extract::State, http::StatusCode};
use mailent_domain::{PolicySimulationRequest, PolicySimulationResult};

use crate::{
    simulation::{PolicyPackSummary, list_available_policies, run_simulation},
    state::AppState,
};

pub async fn list_policies_handler() -> Json<Vec<PolicyPackSummary>> {
    Json(list_available_policies())
}

pub async fn simulate_policy_handler(
    State(state): State<AppState>,
    Json(req): Json<PolicySimulationRequest>,
) -> Result<Json<PolicySimulationResult>, (StatusCode, String)> {
    let result = run_simulation(&state, req).await?;
    Ok(Json(result))
}
