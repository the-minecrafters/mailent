use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
};
use mailent_domain::Organization;

use crate::{auth::ExecutionContext, state::AppState};

pub async fn get_current_organization_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<ExecutionContext>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let org_id = ctx
        .organization_id
        .unwrap_or(mailent_domain::DEFAULT_ORG_ID);
    let org = state
        .organizations
        .find_by_id(org_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .unwrap_or_else(Organization::default);
    Ok(Json(org))
}
