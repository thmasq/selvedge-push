pub mod health;
pub mod heartbeat;
pub mod notify;

use std::time::Duration;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, Method, Request, StatusCode};
use axum::routing::{get, post};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::AppState;

/// Global maximum request body size across all routes (16 KiB).
pub const MAX_BODY_BYTES: usize = 16 * 1024;

/// Maximum wall-clock duration for handling an incoming HTTP request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Global cap on concurrently executing HTTP requests.
const MAX_CONCURRENT_REQUESTS: usize = 256;

/// Builds the Axum router with global body limits, timeouts, concurrency caps,
/// tracing, and scoped CORS.
///
/// # Panics
/// Panics if `state.config.cors_allowed_origin` is not a valid HTTP header value.
pub fn build_router(state: AppState) -> Router {
    let allowed_origin = HeaderValue::from_str(&state.config.cors_allowed_origin)
        .expect("CORS_ALLOWED_ORIGIN must be a valid HTTP header value");

    let heartbeat_cors = CorsLayer::new()
        .allow_origin(allowed_origin)
        .allow_methods([Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([CONTENT_TYPE]);

    let heartbeat_routes = Router::new()
        .route(
            "/heartbeat",
            post(heartbeat::record_heartbeat).delete(heartbeat::clear_heartbeat),
        )
        .route("/heartbeat/clear", post(heartbeat::clear_heartbeat))
        .layer(heartbeat_cors);

    let trace_layer = TraceLayer::new_for_http().make_span_with(|req: &Request<_>| {
        tracing::info_span!(
            "http_request",
            method = %req.method(),
            path = %req.uri().path(),
        )
    });

    Router::new()
        .route("/health", get(health::health))
        .route("/_matrix/push/v1/notify", post(notify::notify))
        .merge(heartbeat_routes)
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(DefaultBodyLimit::disable())
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_REQUESTS))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(trace_layer)
        .with_state(state)
}
