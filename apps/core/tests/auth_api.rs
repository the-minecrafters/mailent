use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use mailent_core::{
    AppState,
    api::create_router,
    auth::{AuthConfig, protect},
};
use tower::ServiceExt;

#[tokio::test]
async fn cloud_routes_reject_missing_and_forged_credentials() {
    let auth = AuthConfig::new(
        "https://invalid.supabase.co".into(),
        "sb_publishable_test".into(),
        vec!["owner@test.invalid".into()],
    );
    let state = AppState::new();
    let app = protect(create_router(state.clone()), Some(auth), state);
    for path in ["/ready", "/api/v1/assets", "/api/v1/reports/archived"] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/auth/config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn authorization_uses_verified_email_and_confirmation() {
    use axum::{Json, Router, routing::get};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mock = Router::new().route("/auth/v1/user", get(|headers: axum::http::HeaderMap| async move {
        let token = headers.get("authorization").unwrap().to_str().unwrap();
        match token {
            "Bearer valid" => (StatusCode::OK, Json(serde_json::json!({"email":"owner@test.invalid", "email_confirmed_at":"2026-09-23T00:00:00Z", "is_anonymous": false}))),
            "Bearer unconfirmed" => (StatusCode::OK, Json(serde_json::json!({"email":"owner@test.invalid"}))),
            "Bearer outsider" => (StatusCode::OK, Json(serde_json::json!({"email":"someone@test.invalid", "email_confirmed_at":"2026-09-23T00:00:00Z", "user_metadata":{"email":"owner@test.invalid"}}))),
            _ => (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"message":"Invalid JWT"}))),
        }
    }));
    let task = tokio::spawn(async move {
        axum::serve(listener, mock).await.unwrap();
    });
    let state2 = AppState::new();
    let app = protect(
        create_router(state2.clone()),
        Some(AuthConfig::new(
            format!("http://{addr}"),
            "test-key".into(),
            vec!["owner@test.invalid".into()],
        )),
        state2,
    );
    for (token, expected) in [
        ("valid", StatusCode::OK),
        ("unconfirmed", StatusCode::FORBIDDEN),
        ("outsider", StatusCode::FORBIDDEN),
        ("forged", StatusCode::UNAUTHORIZED),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/assets")
                    .header("Authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{token}");
    }
    task.abort();
}

#[tokio::test]
async fn spa_is_public_while_the_api_stays_private() {
    use tower_http::services::{ServeDir, ServeFile};
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("index.html"), "<h1>Mailent</h1>").unwrap();
    let state3 = AppState::new();
    let app = protect(
        create_router(state3.clone()),
        Some(AuthConfig::new(
            "https://invalid.supabase.co".into(),
            "sb_publishable_test".into(),
            vec!["owner@test.invalid".into()],
        )),
        state3,
    )
    .fallback_service(
        ServeDir::new(directory.path())
            .fallback(ServeFile::new(directory.path().join("index.html"))),
    );
    for path in ["/", "/workspace/overview", "/workspace/captures/anything"] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
    }
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/assessments")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn provider_check_distinguishes_live_responses_from_fallback() {
    use http_body_util::BodyExt;
    use mailent_decision::{DecisionError, DecisionProvider, JevProvider};
    use mailent_domain::{DecisionContext, DecisionResult};
    use std::sync::Arc;
    struct Provider(bool);
    #[async_trait::async_trait]
    impl DecisionProvider for Provider {
        async fn assess(&self, context: DecisionContext) -> Result<DecisionResult, DecisionError> {
            assert!(context.findings.is_empty());
            assert_eq!(
                context.metadata,
                serde_json::json!({"purpose": "connection_check"})
            );
            let mut result = JevProvider::deterministic_fallback(&context);
            if self.0 {
                result.provider_info = "jev:openjev-latest".into();
            }
            Ok(result)
        }
    }
    for connected in [false, true] {
        let mut state = AppState::new();
        state.decision_provider_name = "jev".into();
        state.decision_provider = Arc::new(Provider(connected));
        let app = create_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/decisions/check")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["connected"], connected);
    }
}

#[tokio::test]
async fn guest_mode_allows_in_memory_access_without_credentials() {
    let auth = AuthConfig::new(
        "https://invalid.supabase.co".into(),
        "sb_publishable_test".into(),
        vec!["owner@test.invalid".into()],
    );
    let state4 = AppState::new();
    let app = protect(create_router(state4.clone()), Some(auth), state4);

    // With X-Mailent-Guest header, unauthenticated requests are allowed
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/assessments")
                .header("X-Mailent-Guest", "true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // With Authorization: Bearer guest, requests are also allowed in guest mode
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/assets")
                .header("Authorization", "Bearer guest")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
