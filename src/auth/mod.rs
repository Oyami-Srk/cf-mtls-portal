//! OIDC authorization flow. Session and transport details live in sibling modules.
mod session;
#[cfg(test)]
mod tests;
mod transport;

pub use session::{LOGIN, SESSION, Session, cookie, set_cookie};
pub(crate) use transport::bounded;
use transport::{OidcHttp, read_secret};

use crate::{
    config::Config,
    crypto,
    error::{AppError, Result},
};
use axum::http::HeaderMap;
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
