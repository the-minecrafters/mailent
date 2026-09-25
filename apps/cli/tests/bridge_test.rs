use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use mailent::bridge::create_bridge_router;
use tower::ServiceExt;

#[tokio::test]
async fn test_bridge_status_endpoint() {
    let app = create_bridge_router();

    let request = Request::builder()
        .method(Method::GET)
        .uri("/status")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert!(json.get("status").is_some());
    assert!(json.get("version").is_some());
    assert!(json.get("zeek_available").is_some());
}

#[tokio::test]
async fn test_bridge_cors_and_pna_allowed_origin() {
    let app = create_bridge_router();

    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri("/api/analyze")
        .header("Origin", "https://mailent.onrender.com")
        .header("Access-Control-Request-Method", "POST")
        .header("Access-Control-Request-Private-Network", "true")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let headers = response.headers();
    assert_eq!(
        headers.get("access-control-allow-origin").unwrap(),
        "https://mailent.onrender.com"
    );
    assert_eq!(
        headers.get("access-control-allow-private-network").unwrap(),
        "true"
    );
}

#[tokio::test]
async fn test_bridge_cors_untrusted_origin_rejected() {
    let app = create_bridge_router();

    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri("/api/analyze")
        .header("Origin", "https://malicious-site.example.com")
        .header("Access-Control-Request-Method", "POST")
        .header("Access-Control-Request-Private-Network", "true")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let headers = response.headers();
    // Untrusted origin must NOT receive CORS allow headers
    assert!(headers.get("access-control-allow-origin").is_none());
    assert!(headers.get("access-control-allow-private-network").is_none());
}

#[tokio::test]
async fn test_bridge_analyze_empty_body_rejected() {
    let app = create_bridge_router();

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/analyze")
        .header("Content-Type", "application/json")
        .body(Body::from("{}"))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_bridge_analyze_invalid_pcap_rejected() {
    let app = create_bridge_router();

    let fake_data = "not a valid pcap capture header at all";
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/analyze?file_name=test.pcap")
        .header("Content-Type", "application/octet-stream")
        .body(Body::from(fake_data.as_bytes()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("not a valid PCAP or PCAPNG")
    );
}
