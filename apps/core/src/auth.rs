//! Private workspace access. Supabase verifies the token; the server owns authorization.
use axum::{
    Json, Router,
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    routing::get,
};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};

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
            (Some(url), Some(key), Some(emails)) if url.starts_with("https://") && key.starts_with("sb_publishable_") => {
                let allowed: Vec<_> = emails.split(',').filter(|s| s.contains('@')).map(str::to_owned).collect();
                if allowed.is_empty() { return Err("MAILENT_ALLOWED_EMAILS must contain a workspace member".into()); }
                let mut config = Self::new(url, key, allowed);
                config.collector_token = std::env::var("MAILENT_COLLECTOR_TOKEN").ok().filter(|s| s.len() >= 32);
                Ok(Some(config))
            }
            _ => Err("Set MAILENT_SUPABASE_URL, MAILENT_SUPABASE_PUBLISHABLE_KEY and MAILENT_ALLOWED_EMAILS before starting cloud mode".into()),
        }
    }
}

#[derive(Deserialize)]
struct VerifiedUser {
    email: Option<String>,
    email_confirmed_at: Option<String>,
    #[serde(default)]
    is_anonymous: bool,
}

async fn authorize(
    State(config): State<Arc<AuthConfig>>,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, &'static str)> {
    if request.uri().path() == "/health" {
        return Ok(next.run(request).await);
    }
    let token = request
        .headers()
        .get("authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or((StatusCode::UNAUTHORIZED, "Sign in to access this workspace"))?;
    let ingest = request.method() == axum::http::Method::POST
        && matches!(
            request.uri().path(),
            "/api/v1/observations" | "/api/v1/sensors/heartbeat"
        );
    if ingest
        && config.collector_token.as_ref().is_some_and(|secret| {
            use sha2::{Digest, Sha256};
            let expected = Sha256::digest(secret.as_bytes());
            let actual = Sha256::digest(token.as_bytes());
            expected
                .iter()
                .zip(actual.iter())
                .fold(0u8, |diff, (a, b)| diff | (a ^ b))
                == 0
        })
    {
        return Ok(next.run(request).await);
    }
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
            .is_some_and(|email| config.allowed_emails.contains(&email.to_lowercase()))
    {
        return Err((
            StatusCode::FORBIDDEN,
            "This account does not have access to this workspace",
        ));
    }
    Ok(next.run(request).await)
}

pub fn protect(router: Router, config: Option<AuthConfig>) -> Router {
    let public = config.as_ref().map(|config| serde_json::json!({"enabled": true, "url": config.url, "publishable_key": config.publishable_key})).unwrap_or_else(|| serde_json::json!({"enabled": false}));
    let router = if let Some(config) = config {
        router.layer(middleware::from_fn_with_state(Arc::new(config), authorize))
    } else {
        router
    };
    router.route("/auth/config", get(move || async { Json(public) }))
}
