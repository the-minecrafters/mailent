use std::net::SocketAddr;

use axum::{
    Json, Router,
    extract::{FromRequest, Multipart, Query, Request},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::AsyncWriteExt;
use tracing::info;

use crate::credentials::load_credentials;
use crate::engine::{AnalysisOptions, execute_capture_analysis, locate_zeek};

#[derive(Debug, Serialize)]
pub struct BridgeStatusResponse {
    pub status: String,
    pub version: String,
    pub device_name: Option<String>,
    pub device_id: Option<String>,
    pub server_url: Option<String>,
    pub zeek_available: bool,
}

#[derive(Debug, Deserialize)]
pub struct JsonAnalyzeRequest {
    pub pcap_base64: Option<String>,
    pub file_name: Option<String>,
    pub title: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct QueryAnalyzeParams {
    pub file_name: Option<String>,
    pub title: Option<String>,
}

fn is_origin_allowed(origin: &str) -> bool {
    let normalized = origin.trim_end_matches('/');

    // Standard dev & prod origins
    if normalized == "https://mailent.onrender.com"
        || normalized == "http://localhost"
        || normalized == "http://127.0.0.1"
        || (normalized.starts_with("http://localhost:")
            && normalized["http://localhost:".len()..]
                .chars()
                .all(|c| c.is_ascii_digit()))
        || (normalized.starts_with("http://127.0.0.1:")
            && normalized["http://127.0.0.1:".len()..]
                .chars()
                .all(|c| c.is_ascii_digit()))
    {
        return true;
    }

    // Configured server origin in device credentials
    if let Some(creds) = load_credentials()
        && creds.server_url.trim_end_matches('/') == normalized {
            return true;
        }

    // Optional environment override
    if let Ok(env_allowed) = std::env::var("MAILENT_ALLOWED_ORIGIN")
        && env_allowed.trim_end_matches('/') == normalized {
            return true;
        }

    false
}

async fn cors_pna_middleware(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let origin_header = req
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let is_options = method == Method::OPTIONS;
    let allowed_origin = origin_header.as_ref().filter(|o| is_origin_allowed(o));

    if is_options {
        let mut res = Response::builder().status(StatusCode::NO_CONTENT);
        if let Some(origin) = allowed_origin {
            let headers = res.headers_mut().unwrap();
            headers.insert(
                "Access-Control-Allow-Origin",
                HeaderValue::from_str(origin).unwrap(),
            );
            headers.insert(
                "Access-Control-Allow-Private-Network",
                HeaderValue::from_static("true"),
            );
            headers.insert(
                "Access-Control-Allow-Methods",
                HeaderValue::from_static("GET, POST, OPTIONS"),
            );
            headers.insert(
                "Access-Control-Allow-Headers",
                HeaderValue::from_static("Content-Type, Authorization, X-Requested-With"),
            );
            headers.insert(
                "Access-Control-Max-Age",
                HeaderValue::from_static("86400"),
            );
        }
        return res.body(axum::body::Body::empty()).unwrap();
    }

    let mut res = next.run(req).await;

    if let Some(origin) = allowed_origin {
        res.headers_mut().insert(
            "Access-Control-Allow-Origin",
            HeaderValue::from_str(origin).unwrap(),
        );
        res.headers_mut().insert(
            "Access-Control-Allow-Private-Network",
            HeaderValue::from_static("true"),
        );
    }

    res
}

async fn status_handler() -> impl IntoResponse {
    let creds = load_credentials();
    let zeek_ok = locate_zeek(None).is_ok();

    match creds {
        Some(c) => Json(BridgeStatusResponse {
            status: "ready".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            device_name: Some(c.device_name),
            device_id: Some(c.device_id.to_string()),
            server_url: Some(c.server_url),
            zeek_available: zeek_ok,
        }),
        None => Json(BridgeStatusResponse {
            status: "unauthenticated".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            device_name: None,
            device_id: None,
            server_url: None,
            zeek_available: zeek_ok,
        }),
    }
}

async fn analyze_handler(
    headers: HeaderMap,
    Query(params): Query<QueryAnalyzeParams>,
    req: Request,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let mut file_name = params.file_name;
    let mut title = params.title;
    let mut capture_bytes: Vec<u8> = Vec::new();

    if content_type.starts_with("multipart/form-data") {
        let mut multipart = Multipart::from_request(req, &())
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({ "error": format!("Invalid multipart form data: {e}") }))))?;

        while let Some(field) = multipart
            .next_field()
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({ "error": format!("Failed to read multipart field: {e}") }))))?
        {
            let name = field.name().unwrap_or("").to_string();
            if name == "file" || name == "capture" || name == "pcap" {
                if file_name.is_none() {
                    file_name = field.file_name().map(|s| s.to_string());
                }
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({ "error": format!("Failed to read capture bytes: {e}") }))))?;
                capture_bytes = bytes.to_vec();
            } else if name == "title" {
                if let Ok(text) = field.text().await {
                    let trimmed = text.trim();
                    if !trimmed.is_empty() {
                        title = Some(trimmed.to_string());
                    }
                }
            } else if name == "file_name"
                && let Ok(text) = field.text().await {
                    let trimmed = text.trim();
                    if !trimmed.is_empty() {
                        file_name = Some(trimmed.to_string());
                    }
                }
        }
    } else if content_type.starts_with("application/json") {
        let body_bytes = axum::body::to_bytes(req.into_body(), 64 * 1024 * 1024)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({ "error": format!("Failed to read request body: {e}") }))))?;
        let json_req: JsonAnalyzeRequest = serde_json::from_slice(&body_bytes)
            .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({ "error": format!("Invalid JSON request: {e}") }))))?;

        if let Some(b64) = json_req.pcap_base64 {
            use base64::Engine;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({ "error": format!("Invalid base64 payload: {e}") }))))?;
            capture_bytes = decoded;
        }
        if json_req.file_name.is_some() {
            file_name = json_req.file_name;
        }
        if json_req.title.is_some() {
            title = json_req.title;
        }
    } else {
        // Raw bytes payload (e.g. application/octet-stream)
        let body_bytes = axum::body::to_bytes(req.into_body(), 64 * 1024 * 1024)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({ "error": format!("Failed to read request body: {e}") }))))?;
        capture_bytes = body_bytes.to_vec();
    }

    if capture_bytes.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "No capture file data provided." })),
        ));
    }

    let default_name = file_name
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| "browser-capture.pcap".to_string());

    // Write to a temporary file for Zeek inspection
    let temp = tempfile::Builder::new()
        .prefix("mailent-companion-")
        .suffix(".pcap")
        .tempfile()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": format!("Failed to create temporary file: {e}") }))))?;

    let mut tokio_file = tokio::fs::File::from_std(temp.reopen().map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": format!("Failed to reopen temporary file: {e}") })))
    })?);

    tokio_file
        .write_all(&capture_bytes)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": format!("Failed to write capture bytes: {e}") }))))?;
    tokio_file
        .flush()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": format!("Failed to flush capture file: {e}") }))))?;

    let outcome = execute_capture_analysis(AnalysisOptions {
        capture_path: temp.path(),
        capture_name: Some(default_name),
        title,
        zeek_override: None,
        verify_checksums: false,
        no_reports: true,
        output_dir: None,
        sync: true,
        server_override: None,
    })
    .await
    .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({ "error": e }))))?;

    Ok(Json(json!({
        "status": "ok",
        "assessment_id": outcome.assessment.id,
        "assessment": outcome.assessment,
        "findings_count": outcome.findings.len(),
        "sessions_count": outcome.sessions.len(),
        "posture_score": outcome.posture_score,
        "posture_grade": outcome.posture_grade,
    })))
}

pub fn create_bridge_router() -> Router {
    Router::new()
        .route("/status", get(status_handler))
        .route("/health", get(status_handler))
        .route("/api/analyze", post(analyze_handler))
        .layer(middleware::from_fn(cors_pna_middleware))
}

pub async fn start_bridge_server(port: u16) -> Result<(), String> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("Failed to bind local companion bridge to {addr}: {e}"))?;

    info!("Mailent local companion bridge listening on http://{}", addr);

    let app = create_bridge_router();
    axum::serve(listener, app)
        .await
        .map_err(|e| format!("Local companion bridge server error: {e}"))?;

    Ok(())
}
