use crate::{
    auth,
    config::{self, Config},
    crypto,
    error::{AppError, Result},
    store::{Store, create_private},
};
use reqwest::Method;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, Instant},
};

pub struct Cloudflare {
    config: Arc<Config>,
    store: Arc<Store>,
    http: reqwest::Client,
    token: Option<SecretString>,
    pinned_cache: tokio::sync::Mutex<Option<(Instant, Vec<Value>)>>,
}
#[derive(Clone)]
pub struct Context {
    pub ruleset: Value,
    pub rule: Value,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    before: String,
    after: String,
    other_hash: String,
    ruleset_id: String,
}
fn normalise(value: &str) -> String {
    let (mut quoted, mut escaped) = (false, false);
    value
        .chars()
        .filter(|c| {
            if quoted {
                if escaped {
                    escaped = false;
                } else if *c == '\\' {
                    escaped = true;
                } else if *c == '"' {
                    quoted = false;
                }
                true
            } else if *c == '"' {
                quoted = true;
                true
            } else {
                !c.is_ascii_whitespace()
            }
        })
        .collect()
}
fn others(ruleset: &Value, rule_id: &str) -> Result<String> {
    let rules = ruleset["rules"].as_array().ok_or_else(AppError::remote)?;
    Ok(crypto::hash(serde_json::to_vec(
        &rules
            .iter()
            .filter(|r| r["id"] != rule_id)
            .collect::<Vec<_>>(),
    )?))
}
fn verify_intent(context: &Context, intent: &Intent, rule_id: &str) -> Result<()> {
    if context.ruleset["id"] != intent.ruleset_id
        || others(&context.ruleset, rule_id)? != intent.other_hash
        || context.rule["action"] != "block"
        || context.rule["enabled"] == false
        || context.rule["expression"].as_str().map(normalise) != Some(normalise(&intent.after))
    {
        return Err(AppError::conflict(
            "policy_uncertain",
            "上次写入尚未确认，停止后续写入，请管理员核对。",
        ));
    }
    Ok(())
}
impl Cloudflare {
    pub fn new(config: Arc<Config>, store: Arc<Store>, http: reqwest::Client) -> Result<Self> {
        let token = match std::env::var("CLOUDFLARE_API_TOKEN") {
            Ok(value) => {
                let secret = SecretString::from(value);
                let value = secret.expose_secret();
                if !(20..=256).contains(&value.len())
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                {
                    return Err(AppError::bad(
                        "token_format",
                        "Cloudflare 环境变量格式无效。",
                    ));
                }
                Some(secret)
            }
            Err(std::env::VarError::NotPresent) => None,
            Err(_) => {
                return Err(AppError::bad(
                    "token_format",
                    "Cloudflare 环境变量编码无效。",
                ));
            }
        };
        Ok(Self {
            config,
            store,
            http,
            token,
            pinned_cache: tokio::sync::Mutex::new(None),
        })
    }
    pub fn configured(&self) -> bool {
        self.token.is_some()
    }
    pub async fn request(&self, path: &str, method: Method, body: Option<Value>) -> Result<Value> {
        let token = self.token.as_ref().ok_or(AppError(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "not_configured",
            "签发服务尚未配置，请联系管理员。",
        ))?;
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}{}",
            self.config.cloudflare.zone_id, path
        );
        let mut request = self
            .http
            .request(method, url)
            .bearer_auth(token.expose_secret());
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.map_err(|_| AppError::remote())?;
        let (status, _, bytes) = auth::bounded(response, 2 * 1024 * 1024).await?;
        let result: Value = serde_json::from_slice(&bytes).map_err(|_| AppError::remote())?;
        if !status.is_success() || result["success"] != true {
            return Err(AppError::remote());
        }
        result.get("result").cloned().ok_or_else(AppError::remote)
    }
    pub async fn certificate(&self, id: &str) -> Result<Value> {
        if uuid::Uuid::parse_str(id).is_err() {
            return Err(AppError::internal());
        }
        self.request(&format!("/client_certificates/{id}"), Method::GET, None)
            .await
    }
    pub async fn list(&self, status: &str) -> Result<Vec<Value>> {
        if !["all", "active"].contains(&status) {
            return Err(AppError::internal());
        }
        let mut result = Vec::new();
        for page in 1..=20 {
            let batch = self
                .request(
                    &format!("/client_certificates?per_page=50&status={status}&page={page}"),
                    Method::GET,
                    None,
                )
                .await?;
            let batch = batch.as_array().ok_or_else(AppError::remote)?;
            result.extend(batch.iter().cloned());
            if batch.len() < 50 {
                return Ok(result);
            }
        }
        Err(AppError::conflict(
            "remote_limit",
            "证书数量超过核对范围，需要管理员处理。",
        ))
    }
    async fn raw_context(&self) -> Result<Context> {
        let ruleset = self
            .request(
                "/rulesets/phases/http_request_firewall_custom/entrypoint",
                Method::GET,
                None,
            )
            .await?;
        if !ruleset["id"].as_str().is_some_and(|v| config::hex(v, 32)) {
            return Err(AppError::remote());
        }
        let rule = ruleset["rules"]
            .as_array()
            .and_then(|rs| {
                rs.iter()
                    .find(|r| r["id"] == self.config.cloudflare.rule_id)
            })
            .cloned()
            .ok_or_else(|| AppError::conflict("rule_changed", "找不到配置的防护规则。"))?;
        if rule["action"] != "block" || rule["enabled"] == false {
            return Err(AppError::conflict(
                "rule_changed",
                "防护规则已变化，停止自动更新。",
            ));
        }
        Ok(Context { ruleset, rule })
    }
    pub async fn context(&self) -> Result<Context> {
        let context = self.raw_context().await?;
        let actual = context.rule["expression"]
            .as_str()
            .ok_or_else(AppError::remote)?;
        if let Some(pending) = self
            .store
            .setting("pending_policy")?
            .filter(|v| !v.is_empty())
        {
            let intent: Intent = serde_json::from_str(&pending)?;
            verify_intent(&context, &intent, &self.config.cloudflare.rule_id)?;
            self.store.set("expected_rule", &intent.after)?;
            self.store.set("pending_policy", "")?;
        }
        let expected = self
            .store
            .setting("expected_rule")?
            .unwrap_or_else(|| self.config.cloudflare.initial_expression.clone());
        if normalise(actual) != normalise(&expected) {
            return Err(AppError::conflict(
                "rule_changed",
                "规则已由其他操作修改，请管理员核对。",
            ));
        }
        Ok(context)
    }
    fn expression(&self, mut fingerprints: Vec<String>) -> Result<String> {
        fingerprints.extend(
            self.config
                .pinned_certificates
                .iter()
                .map(|p| p.fingerprint.clone()),
        );
        let fingerprints: BTreeSet<_> = fingerprints.into_iter().collect();
        if fingerprints.len() > 100 || fingerprints.iter().any(|f| !config::hex(f, 64)) {
            return Err(AppError::conflict(
                "policy_limit",
                "证书指纹数量或格式不符合要求。",
            ));
        }
        let quoted = |value: &str| format!("\"{value}\"");
        let hosts = &self.config.cloudflare.hostnames;
        let host = if hosts.len() == 1 {
            format!("http.host eq {}", quoted(&hosts[0]))
        } else {
            format!(
                "http.host in {{{}}}",
                hosts
                    .iter()
                    .map(|s| quoted(s))
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        };
        // Empty sets must deny every request; avoid emitting an invalid empty set expression.
        if fingerprints.is_empty() {
            return Ok(format!("({host})"));
        }
        let expression = format!(
            "({host} and (not cf.tls_client_auth.cert_verified or cf.tls_client_auth.cert_revoked or not (cf.tls_client_auth.cert_fingerprint_sha256 in {{{}}})))",
            fingerprints
                .iter()
                .map(|f| quoted(f))
                .collect::<Vec<_>>()
                .join(" ")
        );
        if expression.len() > 4096 {
            return Err(AppError::conflict(
                "policy_limit",
                "规则长度超出限制，请减少域名或设备数量。",
            ));
        }
        Ok(expression)
    }
    pub async fn update(&self, fingerprints: Vec<String>) -> Result<()> {
        let context = self.context().await?;
        let after = self.expression(fingerprints)?;
        let before = context.rule["expression"]
            .as_str()
            .ok_or_else(AppError::remote)?
            .to_owned();
        if normalise(&before) == normalise(&after) {
            return Ok(());
        }
        let ruleset_id = context.ruleset["id"]
            .as_str()
            .ok_or_else(AppError::remote)?
            .to_owned();
        let other_hash = others(&context.ruleset, &self.config.cloudflare.rule_id)?;
        let snapshot = json!({"at":chrono::Utc::now().to_rfc3339(),"rulesetId":ruleset_id,"rule":context.rule});
        create_private(
            &self
                .config
                .data_dir
                .join(format!("rule-before-{}.json", uuid::Uuid::new_v4())),
            &serde_json::to_vec_pretty(&snapshot)?,
        )?;
        let fresh = self.context().await?;
        if fresh.ruleset != context.ruleset {
            return Err(AppError::conflict(
                "rule_changed",
                "操作期间防护规则已变化。",
            ));
        }
        let intent = Intent {
            before,
            after: after.clone(),
            other_hash,
            ruleset_id: ruleset_id.clone(),
        };
        // Durable intent precedes the remote write. A timeout/crash must not become a blind retry.
        self.store
            .set("pending_policy", &serde_json::to_string(&intent)?)?;
        let mut entry = json!({"expression":after,"action":"block","enabled":true,"description":context.rule["description"]});
        if context.rule.get("ref").is_some() {
            entry["ref"] = context.rule["ref"].clone();
        }
        let outcome = self
            .request(
                &format!(
                    "/rulesets/{ruleset_id}/rules/{}",
                    self.config.cloudflare.rule_id
                ),
                Method::PATCH,
                Some(entry),
            )
            .await;
        let observed = self.context().await?;
        if observed.rule["expression"].as_str().map(normalise) != Some(normalise(&after)) {
            return Err(outcome.err().unwrap_or_else(|| {
                AppError::conflict("policy_uncertain", "未确认防护规则写入结果。")
            }));
        }
        Ok(())
    }
    pub async fn pinned(&self) -> Vec<Value> {
        if self.config.pinned_certificates.is_empty() {
            return Vec::new();
        }
        let mut cached = self.pinned_cache.lock().await;
        if let Some((until, values)) = &*cached
            && *until > Instant::now()
        {
            return values.clone();
        }
        let certs = self.list("all").await;
        let values=self.config.pinned_certificates.iter().map(|pin|{
            let cert=certs.as_ref().ok().and_then(|list|list.iter().find(|c|c["fingerprint_sha256"]==pin.fingerprint));
            json!({"name":pin.name,"fingerprint":pin.fingerprint,"status":cert.and_then(|c|c["status"].as_str()).unwrap_or("unverified"),"managed":false})
        }).collect::<Vec<_>>();
        *cached = Some((
            Instant::now() + Duration::from_secs(if certs.is_ok() { 60 } else { 15 }),
            values.clone(),
        ));
        values
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    #[test]
    fn expression_normalisation_preserves_quoted_content() {
        assert_eq!(
            normalise("( http.host eq \"a.example.com\" )"),
            "(http.hosteq\"a.example.com\")"
        );
        assert_ne!(
            normalise("http.user_agent eq \"a b\""),
            normalise("http.user_agent eq \"ab\"")
        );
        assert_ne!(
            normalise(r#"http.user_agent eq "a\" b""#),
            normalise(r#"http.user_agent eq "a\"b""#)
        );
    }
    #[test]
    fn policy_is_generic_bounded_and_deduplicated() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::tests::state(&dir);
        let fp = "a".repeat(64);
        let expression = state.cf.expression(vec![fp.clone(), fp.clone()]).unwrap();
        assert_eq!(expression.matches(&fp).count(), 1);
        assert!(expression.contains("service.example.com"));
        assert!(expression.contains("cert_verified"));
        assert!(expression.contains("cert_revoked"));
        assert!(state.cf.expression(vec!["bad\" or true".into()]).is_err());
        assert_eq!(
            state.cf.expression(Vec::new()).unwrap(),
            "(http.host eq \"service.example.com\")"
        );
    }
    #[test]
    fn uncertain_write_requires_exact_target_and_unchanged_other_rules() {
        let rule_id = "b".repeat(32);
        let rule = json!({"id":rule_id,"expression":"new","action":"block","enabled":true});
        let ruleset = json!({"id":"a".repeat(32),"rules":[rule.clone(),{"id":"c".repeat(32),"expression":"other"}]});
        let context = Context { ruleset, rule };
        let intent = Intent {
            before: "old".into(),
            after: "new".into(),
            other_hash: others(&context.ruleset, &rule_id).unwrap(),
            ruleset_id: "a".repeat(32),
        };
        assert!(verify_intent(&context, &intent, &rule_id).is_ok());
        let mut old = context.clone();
        old.rule["expression"] = json!("old");
        assert!(verify_intent(&old, &intent, &rule_id).is_err());
        let mut drift = context.clone();
        drift.ruleset["rules"][1]["expression"] = json!("changed");
        assert!(verify_intent(&drift, &intent, &rule_id).is_err());
        let mut disabled = context;
        disabled.rule["enabled"] = json!(false);
        assert!(verify_intent(&disabled, &intent, &rule_id).is_err());
    }
}
