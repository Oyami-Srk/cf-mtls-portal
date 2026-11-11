mod api;
mod auth;
mod cloudflare;
mod config;
mod crypto;
mod error;
mod state;
mod store;
#[cfg(test)]
mod tests;

use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use error::{AppError, Result};
use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};

fn security_headers(mut response: Response) -> Response {
    for (key, value) in [
        ("cache-control", "no-store, private"),
        ("pragma", "no-cache"),
        (
            "content-security-policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; worker-src 'none'",
        ),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
        (
            "permissions-policy",
            "camera=(), microphone=(), geolocation=()",
        ),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
    ] {
        response
            .headers_mut()
            .insert(key, HeaderValue::from_static(value));
    }
    response
}
async fn guard(State(s): State<Arc<state::State>>, mut request: Request, next: Next) -> Response {
    let result: Result<Response> = async {
        let _request = s.requests.try_acquire().map_err(|_| AppError::busy())?;
        if request.uri().to_string().len() > 4096 {
            return Err(AppError::bad("uri", "请求地址过长。"));
        }
        if request.uri().path() == "/healthz" {
            return Ok(next.run(request).await);
        }
        if request
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            != Some(s.config.authority().as_str())
        {
            return Err(AppError::bad("host", "请求主机名不匹配。"));
        }
        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip())
            .ok_or_else(AppError::internal)?;
        let ip = s.ip(peer, request.headers());
        s.limit(format!("ip:{ip}"), 120)?;
        if request.uri().path() == "/auth/login" {
            s.limit(format!("login:{ip}"), 10)?;
            s.limit("login:global".into(), 60)?;
        }
        if request.uri().path().starts_with("/api/") {
            let user = s.auth.session(request.headers())?;
            s.limit(format!("read:{}", user.sub), 90)?;
            if request.method() == axum::http::Method::POST {
                s.auth.csrf(request.headers(), &user)?;
                s.limit(format!("action:{}", user.sub), 30)?;
                let content = request
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .trim();
                if content != "application/json" {
                    return Err(AppError::bad("json_required", "请使用 JSON 请求。"));
                }
            }
            request.extensions_mut().insert(user);
        }
        Ok(next.run(request).await)
    }
    .await;
    security_headers(match result {
        Ok(response) => response,
        Err(error) => error.into_response(),
    })
}
async fn login(State(s): State<Arc<state::State>>) -> Result<Response> {
    let (url, cookie) = s.auth.begin().await?;
    let mut response = Redirect::temporary(&url).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        cookie.parse().map_err(|_| AppError::internal())?,
    );
    Ok(response)
}
async fn callback(
    State(s): State<Arc<state::State>>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<auth::Callback>,
) -> Result<Response> {
    let (user, cookie) = s.auth.finish(&headers, query).await?;
    s.store.audit(&user.sub, "login", "", "success")?;
    let mut response = Redirect::to("/").into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        cookie.parse().map_err(|_| AppError::internal())?,
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        auth::set_cookie(auth::LOGIN, "", 0)
            .parse()
            .map_err(|_| AppError::internal())?,
    );
    Ok(response)
}
fn asset(bytes: &'static [u8], mime: &'static str) -> Response {
    ([(header::CONTENT_TYPE, mime)], bytes).into_response()
}
fn router(state: Arc<state::State>) -> Router {
    Router::new()
        .route(
            "/",
            get(|| async {
                asset(
                    include_bytes!("../web/index.html"),
                    "text/html; charset=utf-8",
                )
            }),
        )
        .route(
            "/app.js",
            get(|| async {
                asset(
                    include_bytes!("../web/app.js"),
                    "text/javascript; charset=utf-8",
                )
            }),
        )
        .route(
            "/style.css",
            get(|| async {
                asset(
                    include_bytes!("../web/style.css"),
                    "text/css; charset=utf-8",
                )
            }),
        )
        .route(
            "/vendor/forge.min.js",
            get(|| async {
                asset(
                    include_bytes!("../web/vendor/forge.min.js"),
                    "text/javascript; charset=utf-8",
                )
            }),
        )
        .route(
            "/healthz",
            get(|| async { Json(serde_json::json!({"ok":true})) }),
        )
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
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
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}
#[tokio::main(worker_threads = 2)]
async fn main() {
    tracing_subscriber::fmt().json().with_target(false).init();
    if let Err(error) = run().await {
        tracing::error!(code = error.1, "mtls-portal stopped");
        std::process::exit(1);
    }
}
async fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("healthcheck") if args.len() == 1 => {
            let response = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(2))
                .build()
                .map_err(|_| AppError::internal())?
                .get("http://127.0.0.1:8080/healthz")
                .send()
                .await
                .map_err(|_| AppError::internal())?;
            if !response.status().is_success() {
                return Err(AppError::internal());
            }
            return Ok(());
        }
        Some("check-csr") if args.len() == 3 => {
            let text = std::fs::read_to_string(&args[1])?;
            let spki = crypto::check_csr(&text, &args[2])?;
            println!("CSR valid; SPKI SHA256 {spki}");
            return Ok(());
        }
        Some("import-legacy") if args.len() == 3 => {
            store::Store::import(Path::new(&args[1]), Path::new(&args[2]))?;
            println!("Imported offline database copy; original untouched");
            return Ok(());
        }
        Some("check-config") if args.len() == 2 => {
            config::Config::load(Path::new(&args[1]))
                .map_err(|_| AppError::bad("config", "配置验证失败。"))?;
            println!("Configuration valid");
            return Ok(());
        }
        Some("serve") if args.len() == 2 => (),
        _ => {
            println!(
                "mtls-portal serve <config.toml>\nmtls-portal check-config <config.toml>\nmtls-portal check-csr <csr.pem> <expected-cn>\nmtls-portal import-legacy <offline-source.sqlite3> <new-target.sqlite3>"
            );
            return Ok(());
        }
    }
    let config = config::Config::load(Path::new(&args[1]))
        .map_err(|_| AppError::bad("config", "配置验证失败，请核对示例与部署文档。"))?;
    let listen = config.listen;
    let state = state::State::new(config)?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen,"mtls-portal started");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await?;
    Ok(())
}
async fn shutdown() {
    #[cfg(unix)]
    {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _=tokio::signal::ctrl_c()=>{}, _=signal.recv()=>{} }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
