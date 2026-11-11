use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

#[derive(Debug)]
pub struct AppError(pub StatusCode, pub &'static str, pub &'static str);
pub type Result<T> = std::result::Result<T, AppError>;
impl AppError {
    pub fn bad(code: &'static str, message: &'static str) -> Self {
        Self(StatusCode::BAD_REQUEST, code, message)
    }
    pub fn conflict(code: &'static str, message: &'static str) -> Self {
        Self(StatusCode::CONFLICT, code, message)
    }
    pub fn internal() -> Self {
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "操作未完成，请稍后重试。",
        )
    }
    pub fn remote() -> Self {
        Self(
            StatusCode::BAD_GATEWAY,
            "remote",
            "外部服务未完成请求，请稍后核对结果。",
        )
    }
    pub fn login() -> Self {
        Self(StatusCode::UNAUTHORIZED, "login_required", "请先登录。")
    }
    pub fn denied() -> Self {
        Self(
            StatusCode::FORBIDDEN,
            "forbidden",
            "没有操作权限，或请求来源校验失败。",
        )
    }
    pub fn busy() -> Self {
        Self(
            StatusCode::TOO_MANY_REQUESTS,
            "busy",
            "请求过多，请稍后重试。",
        )
    }
}
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if self.0.is_server_error() {
            tracing::warn!(code = self.1, "request failed");
        }
        (self.0, Json(json!({"error":self.2,"code":self.1}))).into_response()
    }
}
impl From<rusqlite::Error> for AppError {
    fn from(_: rusqlite::Error) -> Self {
        Self::internal()
    }
}
impl From<std::io::Error> for AppError {
    fn from(_: std::io::Error) -> Self {
        Self::internal()
    }
}
impl From<serde_json::Error> for AppError {
    fn from(_: serde_json::Error) -> Self {
        Self::internal()
    }
}
