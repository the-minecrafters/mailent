use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use mailent_storage::StorageError;
use serde::Serialize;

use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct CoverageMetricsResponse {
    pub total_assets: usize,
    pub assets_with_baseline: usize,
    pub total_sessions_sampled: usize,
    pub total_findings: usize,
    pub total_anomalies: usize,
    pub total_investigations: usize,
    pub open_investigations: usize,
    pub mta_sts_monitored_domains: usize,
    pub tlsa_monitored_domains: usize,
    pub baseline_coverage_ratio: f32,
}

fn storage_error(err: StorageError) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

pub async fn get_coverage_metrics_handler(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let assets = state.assets.list_all().await.map_err(storage_error)?;
    let total_assets = assets.len();

    let mut assets_with_baseline = 0;
    for asset in &assets {
        if let Ok(Some(_)) = state.baselines.get_baseline(asset.id).await {
            assets_with_baseline += 1;
        }
    }

    let sessions = state
        .sessions
        .list_recent(500)
        .await
        .map_err(storage_error)?;
    let total_sessions_sampled = sessions.len();

    let findings = state.findings.list_all().await.map_err(storage_error)?;
    let total_findings = findings.len();

    let anomalies = state
        .baselines
        .list_anomalies(None, 500)
        .await
        .map_err(storage_error)?;
    let total_anomalies = anomalies.len();

    let investigations = state
        .investigations
        .list_all(500)
        .await
        .map_err(storage_error)?;
    let total_investigations = investigations.len();
    let open_investigations = investigations
        .iter()
        .filter(|i| i.status == mailent_domain::InvestigationStatus::Open)
        .count();

    // Check unique domains monitored for MTA-STS and TLSA
    let mut mta_sts_monitored_domains = 0;
    let mut tlsa_monitored_domains = 0;
    for asset in &assets {
        for host in &asset.hostnames {
            if let Ok(Some(_)) = state.intelligence.get_mta_sts_policy(host).await {
                mta_sts_monitored_domains += 1;
            }
            if let Ok(records) = state.intelligence.get_tlsa_records(host).await
                && !records.is_empty()
            {
                tlsa_monitored_domains += 1;
            }
        }
    }

    let baseline_coverage_ratio = if total_assets > 0 {
        assets_with_baseline as f32 / total_assets as f32
    } else {
        0.0
    };

    Ok(Json(CoverageMetricsResponse {
        total_assets,
        assets_with_baseline,
        total_sessions_sampled,
        total_findings,
        total_anomalies,
        total_investigations,
        open_investigations,
        mta_sts_monitored_domains,
        tlsa_monitored_domains,
        baseline_coverage_ratio,
    }))
}
