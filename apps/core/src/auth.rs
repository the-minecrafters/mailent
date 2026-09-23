//! Private workspace access. Supabase verifies the token; the server owns authorization.
use axum::{
    Json, Router,
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    routing::get,
};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

use crate::state::AppState;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Actor {
    User {
        user_id: String,
        email: String,
        organization_id: Uuid,
    },
    Device {
        device_id: Uuid,
        name: String,
        organization_id: Uuid,
    },
    System,
    Guest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    pub actor: Actor,
    pub organization_id: Option<Uuid>,
    pub is_persistent: bool,
}

impl ExecutionContext {
    pub fn user(user_id: String, email: String, organization_id: Uuid) -> Self {
        Self {
            actor: Actor::User {
                user_id,
                email,
                organization_id,
            },
            organization_id: Some(organization_id),
            is_persistent: true,
        }
    }

    pub fn device(device_id: Uuid, name: String, organization_id: Uuid) -> Self {
        Self {
            actor: Actor::Device {
                device_id,
                name,
                organization_id,
            },
            organization_id: Some(organization_id),
            is_persistent: true,
        }
    }

    pub fn system(organization_id: Option<Uuid>) -> Self {
        Self {
            actor: Actor::System,
            organization_id: organization_id.or(Some(mailent_domain::DEFAULT_ORG_ID)),
            is_persistent: true,
        }
    }

    pub fn guest() -> Self {
        Self {
            actor: Actor::Guest,
            organization_id: None,
            is_persistent: false,
        }
    }

    pub fn is_persistent(&self) -> bool {
        self.is_persistent
    }

    pub fn is_guest(&self) -> bool {
        matches!(self.actor, Actor::Guest)
    }

    pub fn organization_id(&self) -> Option<Uuid> {
        self.organization_id
    }
}

tokio::task_local! {
    pub static USE_PERSISTENCE: bool;
}

#[derive(Clone)]
pub struct AuthConfig {
    url: String,
    publishable_key: String,
    allowed_emails: Vec<String>,
    client: reqwest::Client,
    collector_token: Option<String>,
}

impl AuthConfig {
    pub fn new(url: String, publishable_key: String, allowed_emails: Vec<String>) -> Self {
        Self {
            collector_token: None,
            url: url.trim_end_matches('/').into(),
            publishable_key,
            allowed_emails: allowed_emails
                .into_iter()
                .map(|email| email.trim().to_lowercase())
                .collect(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(8))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("HTTP client"),
        }
    }

    pub fn from_env(production: bool) -> Result<Option<Self>, String> {
        let url = std::env::var("MAILENT_SUPABASE_URL").ok();
        let key = std::env::var("MAILENT_SUPABASE_PUBLISHABLE_KEY").ok();
        let emails = std::env::var("MAILENT_ALLOWED_EMAILS").ok();
        match (url, key, emails) {
            (None, None, None) if !production => Ok(None),
            (Some(url), Some(key), Some(emails))
                if url.starts_with("https://") && key.starts_with("sb_publishable_") =>
            {
                let allowed: Vec<_> = emails
                    .split(',')
                    .filter(|s| s.contains('@'))
                    .map(str::to_owned)
                    .collect();
                if allowed.is_empty() {
                    return Err("MAILENT_ALLOWED_EMAILS must contain a workspace member".into());
                }
                let mut config = Self::new(url, key, allowed);
                config.collector_token =
                    std::env::var("MAILENT_COLLECTOR_TOKEN").ok().filter(|s| s.len() >= 32);
                Ok(Some(config))
            }
            _ => Err("Set MAILENT_SUPABASE_URL, MAILENT_SUPABASE_PUBLISHABLE_KEY and MAILENT_ALLOWED_EMAILS before starting cloud mode".into()),
        }
    }
}

#[derive(Deserialize)]
struct VerifiedUser {
    #[serde(default)]
    id: Option<String>,
    email: Option<String>,
    email_confirmed_at: Option<String>,
    #[serde(default)]
    is_anonymous: bool,
}

#[derive(Clone)]
struct MiddlewareState {
    config: Option<Arc<AuthConfig>>,
    app_state: AppState,
}

async fn authorize(
    State(state): State<MiddlewareState>,
    mut request: Request,
    next: Next,
) -> Result<Response, (StatusCode, &'static str)> {
    let path = request.uri().path().to_string();
    if path == "/health" || (path == "/ready" && state.config.is_none()) {
        let ctx = ExecutionContext::system(Some(mailent_domain::DEFAULT_ORG_ID));
        request.extensions_mut().insert(ctx.clone());
        return Ok(USE_PERSISTENCE
            .scope(ctx.is_persistent, next.run(request))
            .await);
    }

    // Device authorization challenge creation and polling do not require a bearer token
    if path == "/api/v1/devices/authorize/challenge"
        || path == "/api/v1/devices/authorize/poll"
        || (path.starts_with("/api/v1/devices/authorize/") && !path.ends_with("/approve"))
    {
        let ctx = ExecutionContext::system(Some(mailent_domain::DEFAULT_ORG_ID));
        request.extensions_mut().insert(ctx.clone());
        return Ok(USE_PERSISTENCE
            .scope(ctx.is_persistent, next.run(request))
            .await);
    }

    let is_guest = request.headers().contains_key("x-mailent-guest")
        || request
            .headers()
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .map_or(false, |s| s.contains("guest"))
        || request
            .uri()
            .query()
            .map_or(false, |q| q.contains("guest=true"));

    let token = request
        .headers()
        .get("authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty() && *value != "guest");

    // Check device token (format: mlt_...)
    if let Some(tok) = token {
        if tok.starts_with("mlt_") {
            use sha2::{Digest, Sha256};
            let hash = format!("{:x}", Sha256::digest(tok.as_bytes()));
            if let Ok(Some((device, org_id))) =
                state.app_state.devices.validate_device_token(&hash).await
            {
                let ctx = ExecutionContext::device(device.id, device.name, org_id);
                request.extensions_mut().insert(ctx.clone());
                return Ok(USE_PERSISTENCE
                    .scope(ctx.is_persistent, next.run(request))
                    .await);
            } else {
                return Err((StatusCode::UNAUTHORIZED, "Invalid or revoked device token"));
            }
        }
    }

    // Ingest with collector token
    let ingest = request.method() == axum::http::Method::POST
        && matches!(
            path.as_str(),
            "/api/v1/observations" | "/api/v1/sensors/heartbeat"
        );
    if ingest
        && token.is_some()
        && state
            .config
            .as_ref()
            .and_then(|c| c.collector_token.as_ref())
            .is_some_and(|secret| {
                use sha2::{Digest, Sha256};
                let expected = Sha256::digest(secret.as_bytes());
                let actual = Sha256::digest(token.unwrap().as_bytes());
                expected
                    .iter()
                    .zip(actual.iter())
                    .fold(0u8, |diff, (a, b)| diff | (a ^ b))
                    == 0
            })
    {
        let ctx = ExecutionContext::system(Some(mailent_domain::DEFAULT_ORG_ID));
        request.extensions_mut().insert(ctx.clone());
        return Ok(USE_PERSISTENCE
            .scope(ctx.is_persistent, next.run(request))
            .await);
    }

    if let Some(config) = state.config.as_ref() {
        if let Some(token) = token {
            let response = config
                .client
                .get(format!("{}/auth/v1/user", config.url))
                .header("apikey", &config.publishable_key)
                .bearer_auth(token)
                .send()
                .await
                .map_err(|_| {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Sign-in verification is temporarily unavailable",
                    )
                })?;
            if response.status().is_server_error() {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Sign-in verification is temporarily unavailable",
                ));
            }
            if !response.status().is_success() {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "Your session has expired. Please sign in again",
                ));
            }
            let user: VerifiedUser = response.json().await.map_err(|_| {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Could not verify your session",
                )
            })?;
            if user.is_anonymous
                || user.email_confirmed_at.is_none()
                || !user
                    .email
                    .as_ref()
                    .is_some_and(|email| config.allowed_emails.contains(&email.to_lowercase()))
            {
                return Err((
                    StatusCode::FORBIDDEN,
                    "This account does not have access to this workspace",
                ));
            }

            let user_email = user.email.unwrap_or_default();
            let user_id = user.id.unwrap_or_else(|| user_email.clone());
            let org_id = mailent_domain::DEFAULT_ORG_ID;

            // Ensure member record exists for default org
            let _ = state
                .app_state
                .organizations
                .add_member(&mailent_domain::OrganizationMember {
                    organization_id: org_id,
                    user_id: user_id.clone(),
                    role: "admin".into(),
                    created_at: time::OffsetDateTime::now_utc(),
                })
                .await;

            let ctx = ExecutionContext::user(user_id, user_email, org_id);
            request.extensions_mut().insert(ctx.clone());
            return Ok(USE_PERSISTENCE
                .scope(ctx.is_persistent, next.run(request))
                .await);
        }

        if is_guest {
            let ctx = ExecutionContext::guest();
            request.extensions_mut().insert(ctx.clone());
            return Ok(USE_PERSISTENCE.scope(false, next.run(request)).await);
        }

        return Err((
            StatusCode::UNAUTHORIZED,
            "Sign in to access this workspace, or continue in non-persistent guest mode",
        ));
    }

    // Local mode (no Supabase config required)
    if is_guest {
        let ctx = ExecutionContext::guest();
        request.extensions_mut().insert(ctx.clone());
        return Ok(USE_PERSISTENCE.scope(false, next.run(request)).await);
    }

    let ctx = ExecutionContext::user(
        "local-user".to_string(),
        "analyst@mailent.local".to_string(),
        mailent_domain::DEFAULT_ORG_ID,
    );
    request.extensions_mut().insert(ctx.clone());
    Ok(USE_PERSISTENCE.scope(true, next.run(request)).await)
}

pub fn protect(router: Router, config: Option<AuthConfig>, state: AppState) -> Router {
    let public = config
        .as_ref()
        .map(|config| {
            serde_json::json!({
                "enabled": true,
                "url": config.url,
                "publishable_key": config.publishable_key
            })
        })
        .unwrap_or_else(|| serde_json::json!({"enabled": false}));

    let mw_state = MiddlewareState {
        config: config.map(Arc::new),
        app_state: state,
    };

    let router = router
        .layer(middleware::from_fn_with_state(mw_state, authorize))
        .route("/auth/config", get(move || async { Json(public) }));

    router
}
