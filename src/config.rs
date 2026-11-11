use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};
use url::Url;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub origin: String,
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub oidc_secret_file: PathBuf,
    #[serde(default)]
    pub trusted_proxies: Vec<IpAddr>,
    #[serde(default)]
    pub development_http_loopback: bool,
    pub oidc: Oidc,
    pub cloudflare: Cloudflare,
    #[serde(default)]
    pub pinned_certificates: Vec<Pinned>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Oidc {
    pub issuer: String,
    pub client_id: String,
    pub required_group: String,
    pub allowed_users: Vec<String>,
    #[serde(default)]
    pub allowed_subjects: Vec<String>,
    pub required_amr: Vec<String>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cloudflare {
    pub zone_id: String,
    pub rule_id: String,
    pub hostnames: Vec<String>,
    pub initial_expression: String,
    pub validity_days: u16,
    pub max_devices: u16,
    pub daily_limit: u16,
}
#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Pinned {
    pub name: String,
    pub fingerprint: String,
}

pub fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn hostname(value: &str) -> bool {
    value.len() <= 253
        && value.split('.').count() >= 2
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}
impl Config {
    pub fn load(path: &Path) -> std::result::Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|_| "无法读取配置文件")?;
        let mut c: Self = toml::from_str(&text).map_err(|_| "配置格式错误或含未知字段")?;
        let root = path.parent().unwrap_or(Path::new("."));
        for p in [&mut c.data_dir, &mut c.oidc_secret_file] {
            if p.is_relative() {
                *p = root.join(&*p);
            }
        }
        c.validate()?;
        Ok(c)
    }
    pub fn validate(&self) -> std::result::Result<(), String> {
        let origin = Url::parse(&self.origin).map_err(|_| "origin 无效")?;
        let issuer = Url::parse(&self.oidc.issuer).map_err(|_| "issuer 无效")?;
        let loopback = |url: &Url| {
            url.host_str().is_some_and(|h| {
                h == "localhost" || h.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
            })
        };
        let secure = |url: &Url| {
            url.scheme() == "https"
                || (cfg!(debug_assertions)
                    && self.development_http_loopback
                    && url.scheme() == "http"
                    && loopback(url))
        };
        if self.development_http_loopback
            && (!cfg!(debug_assertions) || !self.listen.ip().is_loopback())
        {
            return Err("HTTP 开发模式仅允许 debug 构建且监听 loopback".into());
        }
        if !secure(&origin)
            || !secure(&issuer)
            || origin.origin().ascii_serialization() != self.origin
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || issuer.query().is_some()
            || issuer.fragment().is_some()
            || !issuer.username().is_empty()
            || issuer.password().is_some()
        {
            return Err("origin 必须是无路径 HTTPS origin，issuer 必须使用 HTTPS".into());
        }
        let cf = &self.cloudflare;
        if !hex(&cf.zone_id, 32)
            || !hex(&cf.rule_id, 32)
            || cf.hostnames.is_empty()
            || cf.hostnames.len() > 20
            || cf.hostnames.iter().any(|h| !hostname(h))
        {
            return Err("Cloudflare 标识或域名无效".into());
        }
        if cf
            .hostnames
            .iter()
            .any(|h| Some(h.as_str()) == origin.host_str() || Some(h.as_str()) == issuer.host_str())
        {
            return Err("领证页与身份中心不能加入本应用的 mTLS 防护规则".into());
        }
        if cf.initial_expression.is_empty()
            || cf.initial_expression.len() > 8192
            || !(1..=365).contains(&cf.validity_days)
            || !(1..=100).contains(&cf.max_devices)
            || !(1..=20).contains(&cf.daily_limit)
        {
            return Err("表达式或签发额度无效".into());
        }
        if self.oidc.client_id.is_empty()
            || self.oidc.required_group.is_empty()
            || self.oidc.allowed_users.is_empty()
            || self.oidc.allowed_users.iter().any(String::is_empty)
            || self.oidc.required_amr.is_empty()
        {
            return Err("OIDC 用户、管理组和 MFA 声明限制不能为空".into());
        }
        if self.pinned_certificates.len() > 100
            || self
                .pinned_certificates
                .iter()
                .any(|p| !hex(&p.fingerprint, 64) || p.name.is_empty())
        {
            return Err("保留证书配置无效".into());
        }
        Ok(())
    }
    pub fn authority(&self) -> String {
        self.origin
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .to_owned()
    }
}
