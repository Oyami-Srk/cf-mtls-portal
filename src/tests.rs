#![allow(clippy::unwrap_used, clippy::expect_used)]
use crate::{
    auth,
    config::Config,
    crypto,
    store::{Device, Store},
};
use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{HeaderMap, HeaderValue, Request, StatusCode},
};
use std::{net::SocketAddr, sync::Arc};
use tower::ServiceExt;

pub fn config() -> Config {
    toml::from_str(include_str!("../config.example.toml")).unwrap()
}
fn row(id: &str, owner: &str) -> Device {
    Device {
        id: id.into(),
        owner: owner.into(),
        name: "device".into(),
        cn: "mtls-device-validation".into(),
        cf_id: None,
        fingerprint: None,
        pem: None,
        expires_at: None,
        status: "issuing".into(),
        created_at: chrono::Utc::now().timestamp_millis(),
        replaced_id: None,
        spki_hash: "a".repeat(64),
        error_code: None,
    }
}
#[test]
fn rejects_unsafe_configuration() {
    let original = config();
    assert!(original.validate().is_ok());
    let mut c = original.clone();
    c.origin = "http://certs.example.com".into();
    assert!(c.validate().is_err());
    let mut c = original.clone();
    c.oidc.issuer = "https://:secret@auth.example.com".into();
    assert!(c.validate().is_err());
    let mut c = original.clone();
    c.cloudflare.hostnames = vec!["certs.example.com".into()];
    assert!(c.validate().is_err());
    let mut c = original.clone();
    c.cloudflare.hostnames = vec!["service.example.com\" or true".into()];
    assert!(c.validate().is_err());
    let mut c = original.clone();
    c.oidc.required_amr.clear();
    assert!(c.validate().is_err());
    let mut c = original;
    c.oidc.allowed_users.clear();
    assert!(c.validate().is_err());
}
#[test]
fn cookies_reject_duplicates_and_malformed_values() {
    let mut h = HeaderMap::new();
    let value = crypto::random();
    h.insert(
        "cookie",
        HeaderValue::from_str(&format!("{}={value}", auth::SESSION)).unwrap(),
    );
    assert_eq!(
        auth::cookie(&h, auth::SESSION).unwrap(),
        Some(value.clone())
    );
    h.append(
        "cookie",
        HeaderValue::from_str(&format!("{}={value}", auth::SESSION)).unwrap(),
    );
    assert!(auth::cookie(&h, auth::SESSION).is_err());
    h.insert(
        "cookie",
        HeaderValue::from_static("__Host-certportal=short"),
    );
    assert!(auth::cookie(&h, auth::SESSION).is_err());
}
#[test]
fn csr_checks_signature_subject_and_input_boundaries() {
    let csr = include_str!("../tests/fixtures/client.csr");
    let cn = "mtls-device-validation";
    let spki = crypto::check_csr(csr, cn).unwrap();
    assert_eq!(spki.len(), 64);
    assert!(crypto::check_csr(csr, "wrong-device").is_err());
    assert!(crypto::check_csr(&format!("{csr}{csr}"), cn).is_err());
    assert!(crypto::check_csr(&"A".repeat(8193), cn).is_err());
    let (_, mut pem) = x509_parser::pem::parse_x509_pem(csr.as_bytes()).unwrap();
    let last = pem.contents.len() - 1;
    pem.contents[last] ^= 1;
    use base64::Engine;
    let corrupted = format!(
        "-----BEGIN CERTIFICATE REQUEST-----\n{}\n-----END CERTIFICATE REQUEST-----\n",
        base64::engine::general_purpose::STANDARD.encode(&pem.contents)
    );
    assert!(crypto::check_csr(&corrupted, cn).is_err());
}
#[test]
fn certificate_must_match_device_key_and_validity() {
    let csr = include_str!("../tests/fixtures/client.csr");
    let cert = include_str!("../tests/fixtures/client.pem");
    let spki = crypto::check_csr(csr, "mtls-device-validation").unwrap();
    let checked =
        crypto::check_certificate(cert, "mtls-device-validation", &spki, u16::MAX).unwrap();
    assert_eq!(checked.fingerprint.len(), 64);
    assert!(crypto::check_certificate(cert, "wrong-device", &spki, u16::MAX).is_err());
    assert!(
        crypto::check_certificate(cert, "mtls-device-validation", &"0".repeat(64), u16::MAX)
            .is_err()
    );
    assert!(crypto::check_certificate(cert, "mtls-device-validation", &spki, 1).is_err());
}
#[test]
fn database_enforces_owner_quota_and_single_writer() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    assert!(Store::open(dir.path()).is_err());
    let first = uuid::Uuid::new_v4().to_string();
    store.insert(&row(&first, "alice"), 1, 5).unwrap();
    assert!(store.device(&first, "bob").is_err());
    assert!(store.devices("bob").unwrap().is_empty());
    assert!(
        store
            .insert(&row(&uuid::Uuid::new_v4().to_string(), "alice"), 1, 5)
            .is_err()
    );
    store.status(&first, "revoked", None).unwrap();
    assert!(
        store
            .insert(&row(&uuid::Uuid::new_v4().to_string(), "alice"), 1, 1)
            .is_err()
    );
}
#[test]
fn incomplete_issuance_survives_restart_as_uncertain() {
    let dir = tempfile::tempdir().unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    {
        let store = Store::open(dir.path()).unwrap();
        store.insert(&row(&id, "alice"), 12, 5).unwrap();
    }
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(
        store.device(&id, "alice").unwrap().status,
        "issue_uncertain"
    );
}
#[test]
fn secret_debug_never_contains_token() {
    let secret = secrecy::SecretString::from("unit-test-not-a-real-token");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("unit-test-not-a-real-token"));
    assert!(debug.contains("REDACTED"));
}
pub fn state(dir: &tempfile::TempDir) -> Arc<crate::state::State> {
    let mut c = config();
    c.data_dir = dir.path().join("data");
    c.oidc_secret_file = dir.path().join("oidc-secret");
    crate::store::create_private(&c.oidc_secret_file, b"unit-test-not-a-real-oidc-secret").unwrap();
    crate::state::State::new(c).unwrap()
}
#[tokio::test]
async fn anonymous_and_spoofed_requests_do_not_reach_issuance() {
    let dir = tempfile::tempdir().unwrap();
    let state = state(&dir);
    let app = crate::http::router(state);
    for (method, path, host, expected) in [
        (
            "GET",
            "/api/devices",
            "certs.example.com",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "POST",
            "/api/issue",
            "certs.example.com",
            StatusCode::UNAUTHORIZED,
        ),
        ("GET", "/", "evil.example.com", StatusCode::BAD_REQUEST),
        ("GET", "/healthz", "localhost", StatusCode::OK),
    ] {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("host", host)
            .header("x-forwarded-user", "admin")
            .header("authorization", "Bearer fake")
            .extension(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), expected);
        assert!(response.headers().contains_key("content-security-policy"));
    }
}
#[tokio::test]
async fn unauthenticated_page_has_no_secrets_or_application_branding() {
    let dir = tempfile::tempdir().unwrap();
    let app = crate::http::router(state(&dir));
    let req = Request::builder()
        .uri("/")
        .header("host", "certs.example.com")
        .extension(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()))
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = String::from_utf8(
        to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("mTLS 证书"));
    assert!(!body.contains("Chat"));
    assert!(!body.contains("unit-test-not-a-real-oidc-secret"));
}

#[tokio::test]
async fn browser_modules_are_served_only_from_the_asset_allowlist() {
    let dir = tempfile::tempdir().unwrap();
    let app = crate::http::router(state(&dir));
    for (path, expected, content_type) in [
        (
            "/assets/js/app.mjs",
            StatusCode::OK,
            Some("text/javascript; charset=utf-8"),
        ),
        (
            "/assets/js/certificates.mjs",
            StatusCode::OK,
            Some("text/javascript; charset=utf-8"),
        ),
        (
            "/assets/vendor/bulma.min.css",
            StatusCode::OK,
            Some("text/css; charset=utf-8"),
        ),
        ("/assets/vendor/LICENSE.bulma", StatusCode::NOT_FOUND, None),
        ("/assets/../config.toml", StatusCode::NOT_FOUND, None),
    ] {
        let request = Request::builder()
            .uri(path)
            .header("host", "certs.example.com")
            .extension(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), expected);
        if let Some(value) = content_type {
            assert_eq!(response.headers()["content-type"], value);
        }
        assert!(response.headers().contains_key("content-security-policy"));
    }
}
