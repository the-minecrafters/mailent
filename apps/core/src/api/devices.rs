use axum::{
    Json,
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use mailent_domain::{Device, DeviceAuthorizationChallenge};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    auth::{Actor, ExecutionContext},
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct CreateChallengeRequest {
    pub device_name: Option<String>,
    pub hostname: Option<String>,
    pub platform: Option<String>,
    pub architecture: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateChallengeResponse {
    pub code: String,
    pub verification_url: String,
    pub expires_at: String,
    pub poll_interval_seconds: u64,
}

#[derive(Debug, Deserialize)]
pub struct PollChallengeRequest {
    pub code: String,
}

pub async fn create_challenge_handler(
    State(state): State<AppState>,
    Json(payload): Json<CreateChallengeRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let raw_suffix = &Uuid::new_v4().simple().to_string()[..8];
    let code = format!("MLT-{}", raw_suffix.to_uppercase());
    let expires_at = OffsetDateTime::now_utc() + time::Duration::minutes(15);

    let challenge = DeviceAuthorizationChallenge {
        code: code.clone(),
        device_name: payload
            .device_name
            .unwrap_or_else(|| "Mailent CLI".to_string()),
        hostname: payload.hostname.unwrap_or_else(|| "unknown".to_string()),
        platform: payload
            .platform
            .unwrap_or_else(|| std::env::consts::OS.to_string()),
        architecture: payload
            .architecture
            .unwrap_or_else(|| std::env::consts::ARCH.to_string()),
        expires_at,
        authorized_at: None,
        authorized_by_user_id: None,
        organization_id: None,
        issued_token: None,
        device_id: None,
    };

    state
        .devices
        .create_challenge(&challenge)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let verification_url = format!("/workspace/installations?code={}", code);
    let expires_at_str = expires_at
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();

    Ok((
        StatusCode::CREATED,
        Json(CreateChallengeResponse {
            code,
            verification_url,
            expires_at: expires_at_str,
            poll_interval_seconds: 2,
        }),
    ))
}

pub async fn get_challenge_handler(
    State(state): State<AppState>,
    Path(code): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let challenge = state
        .devices
        .get_challenge(&code)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Challenge not found".to_string()))?;

    if challenge.expires_at < OffsetDateTime::now_utc() {
        return Err((StatusCode::GONE, "Challenge has expired".to_string()));
    }

    Ok(Json(challenge))
}

pub async fn approve_challenge_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<ExecutionContext>,
    Path(code): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (user_id, org_id) = match &ctx.actor {
        Actor::User {
            user_id,
            organization_id,
            ..
        } => (user_id.clone(), *organization_id),
        Actor::System => (
            "system".to_string(),
            ctx.organization_id
                .unwrap_or(mailent_domain::DEFAULT_ORG_ID),
        ),
        _ => {
            return Err((
                StatusCode::FORBIDDEN,
                "Only authenticated users can approve device authorization".to_string(),
            ));
        }
    };

    let challenge = state
        .devices
        .get_challenge(&code)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Challenge not found".to_string()))?;

    if challenge.expires_at < OffsetDateTime::now_utc() {
        return Err((StatusCode::GONE, "Challenge has expired".to_string()));
    }

    let device_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let device = Device {
        id: device_id,
        organization_id: org_id,
        registered_by_user_id: Some(user_id.clone()),
        name: challenge.device_name.clone(),
        hostname: challenge.hostname.clone(),
        platform: challenge.platform.clone(),
        architecture: challenge.architecture.clone(),
        created_at: now,
        last_seen_at: now,
        revoked_at: None,
        capabilities: vec![],
        version: None,
        agent_enabled: false,
        agent_status: None,
        current_job_id: None,
        completed_jobs_count: 0,
    };

    state
        .devices
        .save_device(&device)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let raw_token = format!("mlt_{}", Uuid::new_v4().simple());
    let token_hash = format!("{:x}", Sha256::digest(raw_token.as_bytes()));

    state
        .devices
        .save_device_token(&token_hash, device_id, org_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state
        .devices
        .approve_challenge(&code, &user_id, org_id, &raw_token, device_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "status": "approved",
        "device": device,
    })))
}

pub async fn poll_challenge_handler(
    State(state): State<AppState>,
    Json(payload): Json<PollChallengeRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let challenge = state
        .devices
        .get_challenge(&payload.code)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Challenge not found".to_string()))?;

    if challenge.expires_at < OffsetDateTime::now_utc() {
        return Err((StatusCode::GONE, "Challenge has expired".to_string()));
    }

    if let Some(token) = challenge.issued_token {
        Ok((
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "approved",
                "token": token,
                "device_id": challenge.device_id,
                "organization_id": challenge.organization_id,
            })),
        ))
    } else {
        Ok((
            StatusCode::ACCEPTED,
            Json(serde_json::json!({
                "status": "pending"
            })),
        ))
    }
}

pub async fn list_devices_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<ExecutionContext>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let org_id = ctx
        .organization_id
        .unwrap_or(mailent_domain::DEFAULT_ORG_ID);
    let devices = state
        .devices
        .list_devices_for_org(org_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let syncs = state
        .assessments
        .latest_installation_syncs(org_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let installations: Vec<_> = devices
        .iter()
        .map(|device| {
            let zeek_version = device
                .capabilities
                .iter()
                .find_map(|c| c.strip_prefix("zeek:"));
            let readiness = if !device.is_active() {
                "revoked"
            } else if zeek_version.is_some()
                && ["analyze", "scan", "monitor"]
                    .iter()
                    .all(|c| device.capabilities.iter().any(|v| v == c))
            {
                "ready"
            } else if device
                .capabilities
                .iter()
                .any(|c| c == "installation_reported")
            {
                "setup_required"
            } else {
                "unknown"
            };
            let mut value = serde_json::to_value(device).unwrap_or_default();
            value["zeek_version"] = serde_json::json!(zeek_version);
            value["readiness"] = serde_json::json!(readiness);
            value["remote_online"] =
                serde_json::json!(installation_online(device, OffsetDateTime::now_utc()));
            value["last_sync_at"] = serde_json::json!(syncs.get(&device.id));
            value
        })
        .collect();
    Ok(Json(installations))
}

/// A login/status request is not proof that a worker is accepting remote work.
pub fn installation_online(device: &mailent_domain::Device, now: OffsetDateTime) -> bool {
    device.is_active()
        && device.agent_enabled
        && matches!(
            device.agent_status.as_deref(),
            Some("idle" | "busy" | "online")
        )
        && device
            .capabilities
            .iter()
            .any(|v| v == "infrastructure_scan")
        && device
            .capabilities
            .iter()
            .filter_map(|v| v.strip_prefix("remote_heartbeat:"))
            .filter_map(|v| {
                OffsetDateTime::parse(v, &time::format_description::well_known::Rfc3339).ok()
            })
            .any(|at| now >= at && now - at <= time::Duration::seconds(45))
}

#[derive(Debug, Deserialize)]
pub struct InstallationStatusRequest {
    pub version: String,
    pub zeek_version: Option<String>,
}

/// Records local CLI setup; it never opts an installation into remote work.
pub async fn report_installation_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<ExecutionContext>,
    Json(req): Json<InstallationStatusRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let Actor::Device { device_id, .. } = ctx.actor else {
        return Err((
            StatusCode::FORBIDDEN,
            "Connect Mailent CLI before reporting installation status.".into(),
        ));
    };
    if req.version.is_empty()
        || req.version.len() > 64
        || req.zeek_version.as_ref().is_some_and(|v| v.len() > 64)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid installation version.".into(),
        ));
    }
    let mut capabilities = vec!["installation_reported".to_string()];
    if let Some(version) = req.zeek_version.filter(|v| {
        v.split('.')
            .next()
            .and_then(|n| n.parse::<u32>().ok())
            .is_some_and(|major| major >= 8)
    }) {
        capabilities.extend(["analyze", "scan", "monitor"].map(str::to_string));
        capabilities.push(format!("zeek:{version}"));
    }
    if let Some(existing) = state
        .devices
        .find_device_by_id(device_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    {
        capabilities.extend(
            existing
                .capabilities
                .into_iter()
                .filter(|v| v == "infrastructure_scan" || v.starts_with("remote_heartbeat:")),
        );
    }
    state
        .devices
        .report_installation(
            device_id,
            req.version,
            capabilities,
            OffsetDateTime::now_utc(),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::json!({"status": "ok"})))
}

pub async fn revoke_device_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<ExecutionContext>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if ctx.is_guest() {
        return Err((StatusCode::FORBIDDEN, "Sign in to manage devices.".into()));
    }
    let org_id = ctx
        .organization_id
        .unwrap_or(mailent_domain::DEFAULT_ORG_ID);
    let device = state
        .devices
        .find_device_by_id(id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Device not found".to_string()))?;

    if device.organization_id != org_id {
        return Err((
            StatusCode::FORBIDDEN,
            "Cannot revoke device from another organization".to_string(),
        ));
    }

    state
        .devices
        .revoke_device(id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    stop_device_jobs(&state, id, org_id).await?;

    Ok(Json(serde_json::json!({
        "status": "revoked",
        "device_id": id,
    })))
}

pub async fn device_status_handler(
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
        .ok()
        .flatten()
        .unwrap_or_default();

    match &ctx.actor {
        Actor::Device {
            device_id, name, ..
        } => Ok(Json(serde_json::json!({
            "authenticated": true,
            "type": "device",
            "device_id": device_id,
            "name": name,
            "organization": {
                "id": org.id,
                "name": org.name,
                "slug": org.slug,
            }
        }))),
        Actor::User { user_id, email, .. } => Ok(Json(serde_json::json!({
            "authenticated": true,
            "type": "user",
            "user_id": user_id,
            "email": email,
            "organization": {
                "id": org.id,
                "name": org.name,
                "slug": org.slug,
            }
        }))),
        Actor::System => Ok(Json(serde_json::json!({
            "authenticated": true,
            "type": "system",
            "organization": {
                "id": org.id,
                "name": org.name,
                "slug": org.slug,
            }
        }))),
        Actor::Guest => Ok(Json(serde_json::json!({
            "authenticated": false,
            "type": "guest",
        }))),
    }
}

async fn stop_device_jobs(
    state: &AppState,
    id: Uuid,
    org_id: Uuid,
) -> Result<(), (StatusCode, String)> {
    state
        .devices
        .update_agent_status(id, Some("revoked".into()), None, false)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    state
        .jobs
        .cancel_active_for_device(org_id, id, OffsetDateTime::now_utc())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(())
}

pub async fn device_logout_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<ExecutionContext>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);

    if let Some(tok) = token {
        if tok.starts_with("mlt_") {
            let hash = format!("{:x}", Sha256::digest(tok.as_bytes()));
            state
                .devices
                .revoke_device_token(&hash)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            if let Actor::Device {
                device_id,
                organization_id,
                ..
            } = ctx.actor
            {
                stop_device_jobs(&state, device_id, organization_id).await?;
            }
        }
    }

    Ok(Json(serde_json::json!({
        "status": "logged_out"
    })))
}
