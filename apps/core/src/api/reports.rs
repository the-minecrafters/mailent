use crate::{auth::ExecutionContext, evidence::EvidenceSnapshot};
use axum::{
    Extension,
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
    let disposition_type = match format {
        ReportFormatQuery::Html => "inline",
        _ => "attachment",
    };
    let disposition = format!(
        "{disposition_type}; filename=\"mailent-report-{}.{}\"",
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

pub async fn archive_report_handler(
    State(state): State<AppState>,
    axum::Json(req): axum::Json<mailent_domain::ArchiveReportRequest>,
) -> Result<axum::Json<mailent_domain::ArchivedReportRecord>, (StatusCode, String)> {
    let evidence = match req.subject_kind {
        PostureSubjectKind::Asset => EvidenceSnapshot::asset(&state, req.subject_id).await,
        PostureSubjectKind::Session => EvidenceSnapshot::session(&state, req.subject_id).await,
        PostureSubjectKind::Investigation => {
            EvidenceSnapshot::investigation(&state, req.subject_id).await
        }
    }
    .map_err(storage_error)?
    .ok_or((
        StatusCode::NOT_FOUND,
        format!("subject {} not found", req.subject_id),
    ))?;

    let report = evidence.report(req.subject_kind, req.subject_id, &state);
    let raw_report_json = serde_json::to_string(&report)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let fingerprint = report.content_fingerprint();
    let now = time::OffsetDateTime::now_utc();

    let record = mailent_domain::ArchivedReportRecord {
        id: Uuid::new_v4(),
        report_id: report.metadata.report_id.clone(),
        subject_kind: req.subject_kind,
        subject_id: req.subject_id,
        title: report.metadata.title.clone(),
        fingerprint,
        generated_at: report.metadata.generated_at,
        archived_at: now,
        archived_by: req.archived_by.unwrap_or_else(|| "analyst".into()),
        notes: req.notes,
        raw_report_json,
    };

    state
        .archived_reports
        .archive(&record)
        .await
        .map_err(storage_error)?;
    Ok(axum::Json(record))
}

pub async fn list_archived_reports_handler(
    State(state): State<AppState>,
) -> Result<axum::Json<Vec<mailent_domain::ArchivedReportSummary>>, (StatusCode, String)> {
    let list = state
        .archived_reports
        .list_all(100)
        .await
        .map_err(storage_error)?;
    Ok(axum::Json(list))
}

pub async fn get_archived_report_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(query): Query<ReportQuery>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let format = query.format.unwrap_or(ReportFormatQuery::Json);
    let record = state
        .archived_reports
        .find_by_id(id)
        .await
        .map_err(storage_error)?
        .ok_or((StatusCode::NOT_FOUND, "Archived report not found".into()))?;

    let report: ForensicReport = serde_json::from_str(&record.raw_report_json).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to parse archived report: {e}"),
        )
    })?;

    let (content_type, body) = render_report(&report, format)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let disposition_type = match format {
        ReportFormatQuery::Html => "inline",
        _ => "attachment",
    };
    let disposition = format!(
        "{disposition_type}; filename=\"mailent-archived-report-{}.{}\"",
        record.report_id,
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

pub async fn get_assessment_report_handler(
    State(state): State<AppState>,
    ctx: Option<Extension<ExecutionContext>>,
    Path(id): Path<Uuid>,
    Query(query): Query<ReportQuery>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let format = query.format.unwrap_or(ReportFormatQuery::Json);
    let org_id = ctx.as_ref().and_then(|Extension(c)| c.organization_id);
    let assessment = if let Some(org_id) = org_id {
        state.assessments.find_by_id_scoped(id, org_id).await
    } else {
        state.assessments.find_by_id(id).await
    }
    .map_err(storage_error)?
    .ok_or((StatusCode::NOT_FOUND, format!("assessment {id} not found")))?;
    let evidence = EvidenceSnapshot::assessment(&state, id)
        .await
        .map_err(storage_error)?
        .ok_or((
            StatusCode::NOT_FOUND,
            format!("assessment {id} evidence not found"),
        ))?;

    let (infra_domain, infra_meta) = match &assessment.source {
        mailent_domain::AssessmentSource::Infrastructure(meta) => {
            let mx_records: Vec<String> = meta
                .discovered_endpoints
                .iter()
                .filter(|e| e.service.eq_ignore_ascii_case("mx"))
                .map(|e| e.host.clone())
                .collect();
            let dnssec_status = meta
                .discovery_evidence
                .iter()
                .find(|d| !d.dnssec_status.is_empty())
                .map(|d| d.dnssec_status.clone())
                .unwrap_or_else(|| "unknown".to_string());
            let mta_sts_mode = assessment
                .metadata
                .get("mta_sts_mode")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let infra_data = mailent_reporting::InfrastructureSection {
                domain: meta.target_domain.clone(),
                mx_records,
                discovered_endpoints: Vec::new(),
                mta_sts_mode,
                mta_sts_policy_details: None,
                tls_rpt_destination: None,
                dnssec_status,
            };
            (Some(meta.target_domain.clone()), Some(infra_data))
        }
        _ => (None, None),
    };

    let (posture, guidance) = evidence.posture(PostureSubjectKind::Asset, id);
    let input = mailent_reporting::ReportInput {
        investigation: evidence.investigation.as_ref(),
        asset: evidence.asset.as_ref(),
        sessions: &evidence.sessions,
        findings: &evidence.findings,
        anomalies: &evidence.anomalies,
        drifts: &evidence.drifts,
        probe_runs: &evidence.probes,
        posture: Some(&posture),
        guidance: &guidance,
        remediation_records: &evidence.remediations,
        policy_name: state.policy_pack.name.clone(),
        policy_version: state.policy_pack.version.clone(),
        assessment_source: Some(match &assessment.source {
            mailent_domain::AssessmentSource::Capture(_) => "capture".to_string(),
            mailent_domain::AssessmentSource::Infrastructure(_) => "infrastructure".to_string(),
        }),
        target_domain: infra_domain,
        infrastructure: infra_meta,
    };
    let title = format!("Forensic Dossier: {}", assessment.title);
    let report = mailent_reporting::build_report(
        title,
        env!("CARGO_PKG_VERSION"),
        &input,
        time::OffsetDateTime::now_utc(),
    );
    let (content_type, body) = render_report(&report, format)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let disposition_type = match format {
        ReportFormatQuery::Html => "inline",
        _ => "attachment",
    };
    let disposition = format!(
        "{disposition_type}; filename=\"mailent-assessment-{}.{}\"",
        id,
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
