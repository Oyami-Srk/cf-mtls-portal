//! HTTP boundary: explicit routes, authentication middleware, and embedded assets.
mod api;
mod assets;
mod login;
mod middleware;

use crate::state;
use axum::{
    Json, Router,
    extract::DefaultBodyLimit,
    http::StatusCode,
    routing::{get, post},
};
use std::{sync::Arc, time::Duration};

pub(crate) fn router(state: Arc<state::State>) -> Router {
    assets::routes()
        .route(
            "/healthz",
            get(|| async { Json(serde_json::json!({"ok":true})) }),
        )
        .route("/auth/login", get(login::login))
        .route("/auth/callback", get(login::callback))
        .route("/api/session", get(api::session))
        .route("/api/devices", get(api::devices))
        .route("/api/logout", post(api::logout))
        .route("/api/check", post(api::check))
        .route("/api/jobs", post(api::jobs))
        .route("/api/issue", post(api::issue))
        .route("/api/devices/{id}/certificate", get(api::certificate))
        .route("/api/devices/{id}/recover", post(api::recover))
        .route("/api/devices/{id}/retry", post(api::retry))
        .route("/api/devices/{id}/revoke", post(api::revoke))
        .fallback(|| async {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error":"页面不存在。","code":"not_found"})),
            )
        })
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(16 * 1024))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(60),
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::guard,
        ))
        .with_state(state)
}
