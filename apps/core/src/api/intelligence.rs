use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use mailent_domain::{
    CtCertificateRecord, CtIntelligenceEvent, IntelligenceRefreshStatus, MtaStsPolicy, MxRecord,
    TlsRptAggregateReport, TlsRptPolicy, TlsaRecord,
};
use mailent_storage::StorageError;
use serde::{Deserialize, Serialize};

use crate::{intelligence_refresh::refresh_domain_intelligence, state::AppState};

#[derive(Debug, Serialize, Deserialize)]
pub struct DomainIntelligenceResponse {
    pub domain: String,
    pub mx_records: Vec<MxRecord>,
    pub tlsa_records: Vec<TlsaRecord>,
    pub mta_sts_policy: Option<MtaStsPolicy>,
    pub tls_rpt_policy: Option<TlsRptPolicy>,
    pub recent_tls_rpt_reports: Vec<TlsRptAggregateReport>,
    pub ct_certificates: Vec<CtCertificateRecord>,
    pub ct_events: Vec<CtIntelligenceEvent>,
    pub refresh_status: Option<IntelligenceRefreshStatus>,
}

fn storage_error(err: StorageError) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

pub async fn get_domain_intelligence_handler(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let domain = domain.trim().to_ascii_lowercase();

    let mx_records = state
        .intelligence
        .get_mx_records(&domain)
        .await
        .map_err(storage_error)?;

    let tlsa_records = state
        .intelligence
        .get_tlsa_records(&domain)
        .await
        .map_err(storage_error)?;

    let mta_sts_policy = state
        .intelligence
        .get_mta_sts_policy(&domain)
        .await
        .map_err(storage_error)?;

    let tls_rpt_policy = state
        .intelligence
        .get_tls_rpt_policy(&domain)
        .await
        .map_err(storage_error)?;

    let recent_tls_rpt_reports = state
        .intelligence
        .list_tls_rpt_reports(Some(&domain), 10)
        .await
        .map_err(storage_error)?;

    let ct_certificates = state
        .intelligence
        .get_ct_certificates(&domain)
        .await
        .map_err(storage_error)?;

    let ct_events = state
        .intelligence
        .list_ct_events(Some(&domain), 20)
        .await
        .map_err(storage_error)?;

    let refresh_status = state
        .intelligence
        .get_refresh_status(&domain)
        .await
        .map_err(storage_error)?;

    let response = DomainIntelligenceResponse {
        domain,
        mx_records,
        tlsa_records,
        mta_sts_policy,
        tls_rpt_policy,
        recent_tls_rpt_reports,
        ct_certificates,
        ct_events,
        refresh_status,
    };

    Ok(Json(response))
}

pub async fn refresh_domain_intelligence_handler(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let domain = domain.trim().to_ascii_lowercase();
    refresh_domain_intelligence(&state, &domain).await;

    // Return the freshly updated status
    get_domain_intelligence_handler(State(state), Path(domain)).await
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImportReportResponse {
    pub status: String,
    pub report_ids: Vec<String>,
}

pub async fn import_tls_rpt_report_handler(
    State(state): State<AppState>,
    body: String,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let reports = mailent_integrations::parse_tls_rpt_json(&body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid TLS-RPT JSON: {e}"),
        )
    })?;

    let mut report_ids = Vec::new();
    for report in &reports {
        report_ids.push(report.id.to_string());
        state
            .intelligence
            .save_tls_rpt_report(report)
            .await
            .map_err(storage_error)?;
    }

    Ok((
        StatusCode::CREATED,
        Json(ImportReportResponse {
            status: "imported".to_string(),
            report_ids,
        }),
    ))
}
