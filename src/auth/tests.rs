#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
#[test]
fn authentication_context_requires_fresh_mfa() {
    let now = chrono::Utc::now();
    let required = vec!["mfa".into()];
    assert!(valid_auth_context(
        Some(now),
        &["pwd".into(), "mfa".into()],
        &required,
        now
    ));
    assert!(!valid_auth_context(None, &["mfa".into()], &required, now));
    assert!(!valid_auth_context(
        Some(now),
        &["pwd".into()],
        &required,
        now
    ));
    assert!(!valid_auth_context(
        Some(now - chrono::Duration::minutes(20)),
        &["mfa".into()],
        &required,
        now
    ));
    assert!(!valid_auth_context(
        Some(now + chrono::Duration::minutes(2)),
        &["mfa".into()],
        &required,
        now
    ));
}
#[test]
fn csrf_requires_origin_token_and_same_origin_context() {
    let dir = tempfile::tempdir().unwrap();
    let state = crate::tests::state(&dir);
    let user = Session {
        sub: "alice".into(),
        name: "alice".into(),
        csrf: crypto::random(),
        until: Instant::now() + Duration::from_secs(60),
        last: Instant::now(),
    };
    let mut headers = HeaderMap::new();
    headers.insert("origin", "https://certs.example.com".parse().unwrap());
    headers.insert("x-csrf-token", user.csrf.parse().unwrap());
    assert!(state.auth.csrf(&headers, &user).is_ok());
    headers.insert("origin", "https://evil.example.com".parse().unwrap());
    assert!(state.auth.csrf(&headers, &user).is_err());
    headers.insert("origin", "https://certs.example.com".parse().unwrap());
    headers.insert("sec-fetch-site", "cross-site".parse().unwrap());
    assert!(state.auth.csrf(&headers, &user).is_err());
    headers.remove("sec-fetch-site");
    headers.remove("x-csrf-token");
    assert!(state.auth.csrf(&headers, &user).is_err());
}
#[tokio::test]
async fn failed_state_consumes_flow_and_blocks_replay() {
    let dir = tempfile::tempdir().unwrap();
    let state = crate::tests::state(&dir);
    let metadata:CoreProviderMetadata=serde_json::from_value(serde_json::json!({
        "issuer":"https://auth.example.com","authorization_endpoint":"https://auth.example.com/authorize","token_endpoint":"https://auth.example.com/token","jwks_uri":"https://auth.example.com/jwks","response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]
    })).unwrap();
    let client = Arc::new(
        CoreClient::from_provider_metadata(
            metadata,
            ClientId::new("mtls-portal".into()),
            Some(ClientSecret::new("not-a-real-secret".into())),
        )
        .set_redirect_uri(
            RedirectUrl::new("https://certs.example.com/auth/callback".into()).unwrap(),
        ),
    );
    let key = crypto::random();
    let (_, verifier) = PkceCodeChallenge::new_random_sha256();
    state.auth.memory.lock().unwrap().flows.insert(
        crypto::hash(&key),
        Flow {
            state: CsrfToken::new("expected-state".into()),
            nonce: Nonce::new_random(),
            verifier,
            until: Instant::now() + Duration::from_secs(60),
            client,
        },
    );
    let mut headers = HeaderMap::new();
    headers.insert("cookie", format!("{LOGIN}={key}").parse().unwrap());
    let callback = || Callback {
        code: Some("unused-code".into()),
        state: Some("wrong-state".into()),
        error: None,
        iss: None,
    };
    let result = state.auth.finish(&headers, callback()).await;
    assert!(matches!(
        result,
        Err(AppError(axum::http::StatusCode::FORBIDDEN, _, _))
    ));
    let result = state.auth.finish(&headers, callback()).await;
    assert!(matches!(
        result,
        Err(AppError(axum::http::StatusCode::UNAUTHORIZED, _, _))
    ));
}
