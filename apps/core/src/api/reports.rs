use crate::evidence::EvidenceSnapshot;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderValue, StatusCode, header},
    response::IntoResponse,
};
use mailent_domain::PostureSubjectKind;
use mailent_reporting::{ForensicReport, render_html, render_pdf, to_json};
use serde::Deserialize;
use uuid::Uuid;

use crate::state::AppState;

pub use mailent_reporting::export::ReportFormat as ReportFormatQuery;

#[derive(Debug, Deserialize)]
pub struct ReportQuery {
    /// Export format; JSON is the default.
    pub format: Option<ReportFormatQuery>,
}

fn storage_error(error: mailent_storage::StorageError) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

fn render_report(
    report: &ForensicReport,
    format: ReportFormatQuery,
) -> Result<(HeaderValue, Vec<u8>), mailent_reporting::ReportError> {
    Ok(match format {
        ReportFormatQuery::Json => (
            HeaderValue::from_static("application/json"),
            to_json(report)?.into_bytes(),
        ),
        ReportFormatQuery::Html => (
            HeaderValue::from_static("text/html; charset=utf-8"),
            render_html(report)?.into_bytes(),
        ),
        ReportFormatQuery::Pdf => (
            HeaderValue::from_static("application/pdf"),
            render_pdf(report)?,
        ),
    })
}

pub async fn get_asset_report_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(query): Query<ReportQuery>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let format = query.format.unwrap_or(ReportFormatQuery::Json);
    let evidence = EvidenceSnapshot::asset(&state, id)
        .await
        .map_err(storage_error)?
        .ok_or((StatusCode::NOT_FOUND, format!("asset {id} not found")))?;
    let report = evidence.report(PostureSubjectKind::Asset, id, &state);
    let (content_type, body) = render_report(&report, format)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let disposition = format!(
        "attachment; filename=\"mailent-report-{}.{}\"",
        report.metadata.report_id,
        match format {
            ReportFormatQuery::Json => "json",
            ReportFormatQuery::Html => "html",
            ReportFormatQuery::Pdf => "pdf",
        }
    );
    Ok((
        [
            (header::CONTENT_TYPE, content_type),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&disposition)
                    .unwrap_or(HeaderValue::from_static("attachment")),
            ),
        ],
        body,
    )
        .into_response())
}

pub async fn get_investigation_report_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(query): Query<ReportQuery>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let format = query.format.unwrap_or(ReportFormatQuery::Json);
    let evidence = EvidenceSnapshot::investigation(&state, id)
        .await
        .map_err(storage_error)?
        .ok_or((
            StatusCode::NOT_FOUND,
            format!("investigation {id} not found"),
        ))?;
    let report = evidence.report(PostureSubjectKind::Investigation, id, &state);
    let (content_type, body) = render_report(&report, format)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let disposition = format!(
        "attachment; filename=\"mailent-investigation-{}-report.{}\"",
        report.metadata.report_id,
        match format {
            ReportFormatQuery::Json => "json",
            ReportFormatQuery::Html => "html",
            ReportFormatQuery::Pdf => "pdf",
        }
    );
    Ok((
        [
            (header::CONTENT_TYPE, content_type),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&disposition)
                    .unwrap_or(HeaderValue::from_static("attachment")),
            ),
        ],
        body,
    )
        .into_response())
}
