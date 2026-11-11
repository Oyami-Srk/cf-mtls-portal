use crate::{
    config::Config,
    crypto,
    error::{AppError, Result},
};
use axum::http::{HeaderMap, header};
use openidconnect::{
    AccessTokenHash, AdditionalClaims, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, UserInfoClaims,
    core::{
        CoreAuthenticationFlow, CoreClient, CoreGenderClaim, CoreJwsSigningAlgorithm,
        CoreProviderMetadata,
    },
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const SESSION: &str = "__Host-certportal";
pub const LOGIN: &str = "__Host-certportal-login";
type Client = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;
struct Flow {
    state: CsrfToken,
    nonce: Nonce,
    verifier: PkceCodeVerifier,
    until: Instant,
    client: Arc<Client>,
}
#[derive(Clone)]
pub struct Session {
    pub sub: String,
    pub name: String,
    pub csrf: String,
    until: Instant,
    last: Instant,
}
#[derive(Default)]
struct Memory {
    flows: HashMap<String, Flow>,
    sessions: HashMap<String, Session>,
}
pub struct Auth {
    config: Arc<Config>,
    http: OidcHttp,
    secret: SecretString,
    memory: Mutex<Memory>,
    provider: tokio::sync::Mutex<Option<(Instant, Arc<Client>)>>,
}
#[derive(Deserialize, Serialize, Clone, Debug)]
struct Groups {
    #[serde(default)]
    groups: Vec<String>,
}
impl AdditionalClaims for Groups {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Callback {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub iss: Option<String>,
}
pub fn read_secret(path: &std::path::Path) -> Result<SecretString> {
    use std::io::Read;
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 4096 {
        return Err(AppError::internal());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(AppError::internal());
        }
    }
    let mut text = Zeroizing::new(String::new());
    std::fs::File::open(path)?
        .take(4097)
        .read_to_string(&mut text)?;
    if text.trim().len() < 20
        || text.trim().len() > 4096
        || text.trim().chars().any(char::is_control)
    {
        return Err(AppError::internal());
    }
    Ok(SecretString::from(text.trim().to_owned()))
}
pub async fn bounded(
    response: reqwest::Response,
    limit: usize,
) -> Result<(reqwest::StatusCode, HeaderMap, Vec<u8>)> {
    let mut response = response;
    if response.content_length().is_some_and(|n| n > limit as u64) {
        return Err(AppError::remote());
    }
    let status = response.status();
    let headers = response.headers().clone();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| AppError::remote())? {
        if bytes.len() + chunk.len() > limit {
            return Err(AppError::remote());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok((status, headers, bytes))
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
#[derive(Clone)]
struct OidcHttp {
    client: reqwest::Client,
    issuer: url::Url,
}
impl<'c> openidconnect::AsyncHttpClient<'c> for OidcHttp {
    type Error = std::io::Error;
    type Future = std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = std::result::Result<openidconnect::HttpResponse, std::io::Error>,
                > + Send
                + 'c,
        >,
    >;
    fn call(&'c self, request: openidconnect::HttpRequest) -> Self::Future {
        Box::pin(async move { self.request(request).await })
    }
}
impl OidcHttp {
    async fn request(
        &self,
        request: openidconnect::HttpRequest,
    ) -> std::result::Result<openidconnect::HttpResponse, std::io::Error> {
        let allowed = &self.issuer;
        let destination = url::Url::parse(&request.uri().to_string())
            .map_err(|_| std::io::Error::other("OIDC endpoint"))?;
        if destination.origin() != allowed.origin()
            || !destination.username().is_empty()
            || destination.password().is_some()
            || destination.fragment().is_some()
        {
            return Err(std::io::Error::other("OIDC endpoint rejected"));
        }
        let req = self
            .client
            .request(request.method().clone(), destination)
            .headers(request.headers().clone())
            .body(request.into_body());
        let response = req
            .send()
            .await
            .map_err(|_| std::io::Error::other("OIDC network"))?;
        let (status, headers, body) = bounded(response, 256 * 1024)
            .await
            .map_err(|_| std::io::Error::other("OIDC response"))?;
        let mut result = axum::http::Response::builder().status(status);
        if let Some(target) = result.headers_mut() {
            *target = headers;
        }
        result
            .body(body)
            .map_err(|_| std::io::Error::other("OIDC response"))
    }
}
impl Auth {
    pub fn new(config: Arc<Config>, http: reqwest::Client) -> Result<Self> {
        let secret = read_secret(&config.oidc_secret_file)?;
        let http = OidcHttp {
            client: http,
            issuer: url::Url::parse(&config.oidc.issuer).map_err(|_| AppError::internal())?,
        };
        Ok(Self {
            config,
            http,
            secret,
            memory: Mutex::new(Memory::default()),
            provider: tokio::sync::Mutex::new(None),
        })
    }
    async fn provider(&self) -> Result<Arc<Client>> {
        let mut cached = self.provider.lock().await;
        if let Some((until, client)) = &*cached
            && *until > Instant::now()
        {
            return Ok(client.clone());
        }
        let metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(self.config.oidc.issuer.clone()).map_err(|_| AppError::internal())?,
            &self.http,
        )
        .await
        .map_err(|_| AppError::remote())?;
        let issuer = url::Url::parse(&self.config.oidc.issuer).map_err(|_| AppError::internal())?;
        for endpoint in [
            Some(metadata.authorization_endpoint().url()),
            metadata.token_endpoint().map(|x| x.url()),
            metadata.userinfo_endpoint().map(|x| x.url()),
        ]
        .into_iter()
        .flatten()
        {
            if endpoint.origin() != issuer.origin() {
                return Err(AppError::denied());
            }
        }
        let client = Arc::new(
            CoreClient::from_provider_metadata(
                metadata,
                ClientId::new(self.config.oidc.client_id.clone()),
                Some(ClientSecret::new(self.secret.expose_secret().to_owned())),
            )
            .set_redirect_uri(
                RedirectUrl::new(format!("{}/auth/callback", self.config.origin))
                    .map_err(|_| AppError::internal())?,
            ),
        );
        *cached = Some((Instant::now() + Duration::from_secs(60), client.clone()));
        Ok(client)
    }
    pub async fn begin(&self) -> Result<(String, String)> {
        let client = self.provider().await?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, state, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("profile".into()))
            .add_scope(Scope::new("groups".into()))
            .set_max_age(Duration::from_secs(900))
            .set_pkce_challenge(challenge)
            .url();
        let key = crypto::random();
        let mut memory = self.memory.lock().map_err(|_| AppError::internal())?;
        memory.flows.retain(|_, f| f.until > Instant::now());
        if memory.flows.len() >= 256 {
            return Err(AppError::busy());
        }
        memory.flows.insert(
            crypto::hash(&key),
            Flow {
                state,
                nonce,
                verifier,
                until: Instant::now() + Duration::from_secs(600),
                client,
            },
        );
        Ok((url.into(), set_cookie(LOGIN, &key, 600)))
    }
    pub async fn finish(&self, headers: &HeaderMap, query: Callback) -> Result<(Session, String)> {
        let key = cookie(headers, LOGIN)?.ok_or_else(AppError::login)?;
        let flow = self
            .memory
            .lock()
            .map_err(|_| AppError::internal())?
            .flows
            .remove(&crypto::hash(key))
            .ok_or_else(AppError::login)?;
        if flow.until < Instant::now()
            || query.error.is_some()
            || !query
                .state
                .is_some_and(|s| crypto::equal(&s, flow.state.secret()))
            || query.iss.is_some_and(|iss| iss != self.config.oidc.issuer)
        {
            return Err(AppError::denied());
        }
        let code = query
            .code
            .filter(|v| !v.is_empty() && v.len() <= 2048)
            .ok_or_else(AppError::denied)?;
        let response = flow
            .client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|_| AppError::internal())?
            .set_pkce_verifier(flow.verifier)
            .request_async(&self.http)
            .await
            .map_err(|_| AppError::denied())?;
        let token = response.id_token().ok_or_else(AppError::denied)?;
        let verifier = flow.client.id_token_verifier().set_allowed_algs([
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            CoreJwsSigningAlgorithm::RsaSsaPssSha256,
            CoreJwsSigningAlgorithm::EcdsaP256Sha256,
        ]);
        let claims = token
            .claims(&verifier, &flow.nonce)
            .map_err(|_| AppError::denied())?;
        let now = chrono::Utc::now();
        let amr = claims
            .auth_method_refs()
            .map(|items| {
                items
                    .iter()
                    .map(|m| m.as_str().to_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if claims.issue_time() > now + chrono::Duration::seconds(30)
            || !valid_auth_context(
                claims.auth_time(),
                &amr,
                &self.config.oidc.required_amr,
                now,
            )
        {
            return Err(AppError::denied());
        }
        if claims.audiences().len() != 1
            || claims
                .authorized_party()
                .is_some_and(|party| party.as_str() != self.config.oidc.client_id)
        {
            return Err(AppError::denied());
        }
        if let Some(expected) = claims.access_token_hash() {
            let actual = AccessTokenHash::from_token(
                response.access_token(),
                token.signing_alg().map_err(|_| AppError::denied())?,
                token
                    .signing_key(&verifier)
                    .map_err(|_| AppError::denied())?,
            )
            .map_err(|_| AppError::denied())?;
            if !crypto::equal(actual.as_str(), expected.as_str()) {
                return Err(AppError::denied());
            }
        }
        let info: UserInfoClaims<Groups, CoreGenderClaim> = flow
            .client
            .user_info(
                response.access_token().clone(),
                Some(claims.subject().clone()),
            )
            .map_err(|_| AppError::denied())?
            .request_async(&self.http)
            .await
            .map_err(|_| AppError::denied())?;
        let username = info
            .preferred_username()
            .map(|u| u.as_str())
            .ok_or_else(AppError::denied)?;
        let sub = claims.subject().as_str();
        if !self.config.oidc.allowed_users.iter().any(|u| u == username)
            || !info
                .additional_claims()
                .groups
                .contains(&self.config.oidc.required_group)
            || (!self.config.oidc.allowed_subjects.is_empty()
                && !self.config.oidc.allowed_subjects.iter().any(|s| s == sub))
        {
            return Err(AppError::denied());
        }
        let session = Session {
            sub: sub.to_owned(),
            name: username.to_owned(),
            csrf: crypto::random(),
            until: Instant::now() + Duration::from_secs(1800),
            last: Instant::now(),
        };
        let sid = crypto::random();
        let mut memory = self.memory.lock().map_err(|_| AppError::internal())?;
        memory
            .sessions
            .retain(|_, s| s.until > Instant::now() && s.last.elapsed() < Duration::from_secs(600));
        if memory.sessions.len() >= 128 {
            return Err(AppError::busy());
        }
        if let Some(old) = cookie(headers, SESSION)? {
            memory.sessions.remove(&crypto::hash(old));
        }
        memory.sessions.insert(crypto::hash(&sid), session.clone());
        Ok((session, set_cookie(SESSION, &sid, 1800)))
    }
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
fn valid_auth_context(
    time: Option<chrono::DateTime<chrono::Utc>>,
    methods: &[String],
    required: &[String],
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    time.is_some_and(|time| {
        time <= now + chrono::Duration::seconds(30) && time >= now - chrono::Duration::seconds(930)
    }) && required.iter().all(|needed| methods.contains(needed))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
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
}
