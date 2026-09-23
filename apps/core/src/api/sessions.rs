use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use mailent_domain::{EmailSession, Finding, ForwardSecrecyState};
use mailent_storage::StorageError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ListSessionsQuery {
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionListItem {
    pub session_id: Uuid,
    pub sensor_id: String,
    pub protocol: String,
    pub client: String,
    pub server: String,
    pub starttls_state: Option<String>,
    pub tls_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub forward_secrecy: ForwardSecrecyState,
    pub certificate_state: String,
    pub findings_count: usize,
    #[serde(with = "time::serde::rfc3339")]
    pub first_seen: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen: time::OffsetDateTime,
    pub has_capture_evidence: bool,
    pub session: EmailSession,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionDetailResponse {
    pub session: EmailSession,
    pub findings: Vec<Finding>,
    pub forward_secrecy: ForwardSecrecyState,
    pub certificate_state: String,
}

pub fn derive_forward_secrecy(session: &EmailSession) -> ForwardSecrecyState {
    session
        .key_exchange
        .as_ref()
        .map(|kx| kx.provides_forward_secrecy())
        .unwrap_or(ForwardSecrecyState::Unknown)
}

pub fn derive_certificate_state(session: &EmailSession) -> String {
    match &session.certificate {
        None => "unavailable".to_string(),
        Some(cert) => {
            if cert.validity.not_after < session.last_seen {
                "expired".to_string()
            } else {
                "valid".to_string()
            }
        }
    }
}

pub async fn list_sessions_handler(
    State(state): State<AppState>,
    Query(query): Query<ListSessionsQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let limit = query.limit.unwrap_or(100).min(500);
    let sessions = state
        .sessions
        .list_recent(limit)
        .await
        .map_err(storage_error)?;

    let all_findings = state.findings.list_all().await.map_err(storage_error)?;

    let items: Vec<SessionListItem> = sessions
        .into_iter()
        .map(|session| {
            let findings_count = all_findings
                .iter()
                .filter(|f| {
                    f.evidence
                        .iter()
                        .any(|e| e.session_id == Some(session.session_id))
                })
                .count();

            let forward_secrecy = derive_forward_secrecy(&session);
            let certificate_state = derive_certificate_state(&session);
            let has_capture_evidence = session.capture.is_some();

            SessionListItem {
                session_id: session.session_id,
                sensor_id: session.sensor_id.clone(),
                protocol: session.protocol.to_string(),
                client: format!("{}:{}", session.flow.src_ip, session.flow.src_port),
                server: format!("{}:{}", session.flow.dst_ip, session.flow.dst_port),
                starttls_state: session.starttls_state.map(|s| s.to_string()),
                tls_version: session.tls_version.as_ref().map(|v| v.to_string()),
                cipher_suite: session.cipher_suite.as_ref().map(|c| c.name.clone()),
                forward_secrecy,
                certificate_state,
                findings_count,
                first_seen: session.first_seen,
                last_seen: session.last_seen,
                has_capture_evidence,
                session,
            }
        })
        .collect();

    Ok(Json(items))
}

pub async fn get_session_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let session = state
        .sessions
        .find_by_id(id)
        .await
        .map_err(storage_error)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("session {id} not found")))?;

    let all_findings = state.findings.list_all().await.map_err(storage_error)?;

    let findings = all_findings
        .into_iter()
        .filter(|f| {
            f.evidence
                .iter()
                .any(|e| e.session_id == Some(session.session_id))
        })
        .collect();

    let forward_secrecy = derive_forward_secrecy(&session);
    let certificate_state = derive_certificate_state(&session);

    Ok(Json(SessionDetailResponse {
        session,
        findings,
        forward_secrecy,
        certificate_state,
    }))
}

fn storage_error(error: StorageError) -> (StatusCode, String) {
    match error {
        StorageError::Conflict(message) => (StatusCode::CONFLICT, message),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage operation failed".into(),
        ),
    }
}
