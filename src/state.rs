use crate::{
    auth::Auth,
    cloudflare::Cloudflare,
    config::Config,
    crypto,
    error::{AppError, Result},
    store::Store,
};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct Job {
    pub id: String,
    pub name: String,
    pub cn: String,
    pub owner: String,
    pub replaced_id: Option<String>,
    pub until: Instant,
}
pub struct State {
    pub config: Arc<Config>,
    pub store: Arc<Store>,
    pub auth: Auth,
    pub cf: Cloudflare,
    pub writes: tokio::sync::Mutex<()>,
    pub requests: tokio::sync::Semaphore,
    jobs: Mutex<HashMap<String, Job>>,
    rates: Mutex<HashMap<String, (Instant, u16)>>,
}
impl State {
    pub fn new(config: Config) -> Result<Arc<Self>> {
        let config = Arc::new(config);
        let store = Arc::new(Store::open(&config.data_dir)?);
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(!config.development_http_loopback)
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .retry(reqwest::retry::never())
            .build()
            .map_err(|_| AppError::internal())?;
        let auth = Auth::new(config.clone(), http.clone())?;
        let cf = Cloudflare::new(config.clone(), store.clone(), http)?;
        Ok(Arc::new(Self {
            config,
            store,
            auth,
            cf,
            writes: tokio::sync::Mutex::new(()),
            requests: tokio::sync::Semaphore::new(128),
            jobs: Mutex::new(HashMap::new()),
            rates: Mutex::new(HashMap::new()),
        }))
    }
    pub fn limit(&self, key: String, max: u16) -> Result<()> {
        let mut rates = self.rates.lock().map_err(|_| AppError::internal())?;
        let now = Instant::now();
        rates.retain(|_, (until, _)| *until > now);
        if rates.len() >= 4096 && !rates.contains_key(&key) {
            return Err(AppError::busy());
        }
        let value = rates
            .entry(key)
            .or_insert((now + Duration::from_secs(60), 0));
        value.1 = value.1.saturating_add(1);
        if value.1 > max {
            return Err(AppError::busy());
        }
        Ok(())
    }
    pub fn ip(&self, peer: IpAddr, headers: &axum::http::HeaderMap) -> IpAddr {
        if self.config.trusted_proxies.contains(&peer) {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse().ok())
                .unwrap_or(peer)
        } else {
            peer
        }
    }
    pub fn job(
        &self,
        owner: &str,
        name: String,
        replaced_id: Option<String>,
    ) -> Result<(String, String)> {
        let mut jobs = self.jobs.lock().map_err(|_| AppError::internal())?;
        let now = Instant::now();
        jobs.retain(|_, j| j.until > now);
        if jobs.len() >= 512 || jobs.values().filter(|j| j.owner == owner).count() >= 8 {
            return Err(AppError::busy());
        }
        let id = uuid::Uuid::new_v4().to_string();
        let key = crypto::random();
        let cn = format!("mtls-device-{id}");
        jobs.insert(
            crypto::hash(&key),
            Job {
                id,
                name,
                cn: cn.clone(),
                owner: owner.to_owned(),
                replaced_id,
                until: now + Duration::from_secs(600),
            },
        );
        Ok((key, cn))
    }
    pub fn get_job(&self, key: &str, owner: &str) -> Result<Job> {
        if key.len() != 43 {
            return Err(AppError::bad("job", "签发申请无效。"));
        }
        self.jobs
            .lock()
            .map_err(|_| AppError::internal())?
            .get(&crypto::hash(key))
            .filter(|j| j.owner == owner && j.until > Instant::now())
            .cloned()
            .ok_or_else(|| AppError::bad("job", "签发申请已过期，请重新申请。"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    #[test]
    fn jobs_are_bound_to_owner_and_expiration() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::tests::state(&dir);
        let (key, _) = state.job("alice", "laptop".into(), None).unwrap();
        assert!(state.get_job(&key, "alice").is_ok());
        assert!(state.get_job(&key, "bob").is_err());
        state
            .jobs
            .lock()
            .unwrap()
            .get_mut(&crypto::hash(&key))
            .unwrap()
            .until = Instant::now() - Duration::from_secs(1);
        assert!(state.get_job(&key, "alice").is_err());
    }
    #[test]
    fn spoofed_proxy_headers_do_not_change_remote_ip() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::tests::state(&dir);
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-real-ip", "1.2.3.4".parse().unwrap());
        let peer = "192.0.2.1".parse().unwrap();
        assert_eq!(state.ip(peer, &headers), peer);
        assert_eq!(
            state.ip("127.0.0.1".parse().unwrap(), &headers),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }
}
