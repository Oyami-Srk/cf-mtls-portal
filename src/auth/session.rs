//! Cookie parsing, session lifetime, CSRF, and logout. No OIDC network operations.
use super::Auth;
use crate::{
    crypto,
    error::{AppError, Result},
};
use axum::http::{HeaderMap, header};
use std::time::{Duration, Instant};

pub const SESSION: &str = "__Host-certportal";
pub const LOGIN: &str = "__Host-certportal-login";

#[derive(Clone)]
pub struct Session {
    pub sub: String,
    pub name: String,
    pub csrf: String,
    pub(super) until: Instant,
    pub(super) last: Instant,
}
pub fn cookie(headers: &HeaderMap, name: &str) -> Result<Option<String>> {
    let mut found = None;
    for line in headers.get_all(header::COOKIE) {
        for part in line
            .to_str()
            .map_err(|_| AppError::bad("cookie", "Cookie 格式无效。"))?
            .split(';')
        {
            if let Some((key, value)) = part.trim().split_once('=')
                && key == name
            {
                if found.is_some()
                    || value.len() != 43
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                {
                    return Err(AppError::login());
                }
                found = Some(value.to_owned());
            }
        }
    }
    Ok(found)
}
pub fn set_cookie(name: &str, value: &str, age: u16) -> String {
    format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={age}")
}
impl Auth {
    pub fn session(&self, headers: &HeaderMap) -> Result<Session> {
        let sid = cookie(headers, SESSION)?.ok_or_else(AppError::login)?;
        let mut memory = self.memory.lock().map_err(|_| AppError::internal())?;
        let session = memory
            .sessions
            .get_mut(&crypto::hash(sid))
            .ok_or_else(AppError::login)?;
        if session.until < Instant::now() || session.last.elapsed() > Duration::from_secs(600) {
            return Err(AppError::login());
        }
        session.last = Instant::now();
        Ok(session.clone())
    }
    pub fn csrf(&self, headers: &HeaderMap, session: &Session) -> Result<()> {
        if headers.get(header::ORIGIN).and_then(|v| v.to_str().ok())
            != Some(self.config.origin.as_str())
            || !headers
                .get("x-csrf-token")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| crypto::equal(v, &session.csrf))
            || headers
                .get("sec-fetch-site")
                .is_some_and(|v| v != "same-origin")
        {
            return Err(AppError::denied());
        }
        Ok(())
    }
    pub fn logout(&self, headers: &HeaderMap) -> Result<()> {
        if let Some(sid) = cookie(headers, SESSION)? {
            self.memory
                .lock()
                .map_err(|_| AppError::internal())?
                .sessions
                .remove(&crypto::hash(sid));
        }
        Ok(())
    }
}
