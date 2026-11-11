use crate::{
    error::{AppError, Result},
    state,
};
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderValue, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::{net::SocketAddr, sync::Arc};

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
pub(super) async fn guard(
    State(s): State<Arc<state::State>>,
    mut request: Request,
    next: Next,
) -> Response {
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
