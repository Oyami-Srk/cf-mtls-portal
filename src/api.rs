use crate::{
    auth::{self, Session},
    crypto,
    error::{AppError, Result},
    state::State,
    store::Device,
};
use axum::{
    Extension, Json,
    extract::{FromRequest, Path, Request, State as AppState},
};
use reqwest::Method;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::sync::Arc;

pub struct StrictJson<T>(pub T);
impl<T: DeserializeOwned + Send> FromRequest<Arc<State>> for StrictJson<T> {
    type Rejection = AppError;
    async fn from_request(request: Request, state: &Arc<State>) -> Result<Self> {
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|_| AppError::bad("invalid_json", "请求格式或字段无效。"))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct JobInput {
    name: String,
    replaced_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IssueInput {
    job_id: String,
    csr: String,
}
pub async fn session(
    AppState(s): AppState<Arc<State>>,
    Extension(user): Extension<Session>,
) -> Json<Value> {
    Json(
        json!({"name":user.name,"csrf":user.csrf,"configured":s.cf.configured(),"validityDays":s.config.cloudflare.validity_days}),
    )
}
pub async fn devices(
    AppState(s): AppState<Arc<State>>,
    Extension(user): Extension<Session>,
) -> Result<Json<Value>> {
    let devices = s.store.devices(&user.sub)?;
    Ok(Json(
        json!({"devices":devices,"pinned":s.cf.pinned().await}),
    ))
}
pub async fn logout(
    AppState(s): AppState<Arc<State>>,
    headers: axum::http::HeaderMap,
) -> Result<(axum::http::HeaderMap, Json<Value>)> {
    s.auth.logout(&headers)?;
    let mut result = axum::http::HeaderMap::new();
    result.insert(
        axum::http::header::SET_COOKIE,
        auth::set_cookie(auth::SESSION, "", 0)
            .parse()
            .map_err(|_| AppError::internal())?,
    );
    Ok((result, Json(json!({"ok":true}))))
}
pub async fn check(AppState(s): AppState<Arc<State>>) -> Result<Json<Value>> {
    let _guard = s.writes.try_lock().map_err(|_| AppError::busy())?;
    s.cf.context().await?;
    Ok(Json(json!({"ok":true})))
}
pub async fn jobs(
    AppState(s): AppState<Arc<State>>,
    Extension(user): Extension<Session>,
    StrictJson(input): StrictJson<JobInput>,
) -> Result<Json<Value>> {
    if !s.cf.configured() {
        return Err(AppError::bad("not_configured", "签发服务尚未配置。"));
    }
    let name = input.name.trim().to_owned();
    if name.is_empty() || name.chars().count() > 60 || name.chars().any(|c| {
        c.is_control()
            || matches!(c,'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}'|'\u{200b}'..='\u{200f}')
    }) {
        return Err(AppError::bad(
            "name",
            "名称需要 1–60 个字符，不能包含控制字符。",
        ));
    }
    if let Some(id) = &input.replaced_id
        && s.store.device(id, &user.sub)?.status != "active"
    {
        return Err(AppError::conflict("renewal", "只有可用设备可以续签。"));
    }
    let (key, cn) = s.job(&user.sub, name, input.replaced_id)?;
    let id = cn
        .strip_prefix("mtls-device-")
        .ok_or_else(AppError::internal)?;
    Ok(Json(json!({"jobId":key,"cn":cn,"deviceId":id})))
}
pub async fn issue(
    AppState(s): AppState<Arc<State>>,
    Extension(user): Extension<Session>,
    StrictJson(input): StrictJson<IssueInput>,
) -> Result<Json<Value>> {
    let _guard = s.writes.try_lock().map_err(|_| AppError::busy())?;
    let job = s.get_job(&input.job_id, &user.sub)?;
    if let Ok(existing) = s.store.device(&job.id, &user.sub) {
        if existing.status == "active" && existing.pem.is_some() {
            return Ok(Json(json!({"certificate":existing.pem,"device":existing})));
        }
        return Err(AppError::conflict(
            "submitted",
            "申请已经提交，请核对设备列表，不要重复签发。",
        ));
    }
    let spki = crypto::check_csr(&input.csr, &job.cn)?;
    s.cf.context().await?;
    let device = Device {
        id: job.id.clone(),
        owner: user.sub.clone(),
        name: job.name.clone(),
        cn: job.cn.clone(),
        cf_id: None,
        fingerprint: None,
        pem: None,
        expires_at: None,
        status: "issuing".into(),
        created_at: chrono::Utc::now().timestamp_millis(),
        replaced_id: job.replaced_id,
        spki_hash: spki.clone(),
        error_code: None,
    };
    s.store.insert(
        &device,
        s.config.cloudflare.max_devices,
        s.config.cloudflare.daily_limit,
    )?;
    s.store.audit(&user.sub, "issue", &job.id, "started")?;
    let result =
        s.cf.request(
            "/client_certificates",
            Method::POST,
            Some(json!({"csr":input.csr,"validity_days":s.config.cloudflare.validity_days})),
        )
        .await;
    let result = match result {
        Ok(v) => v,
        Err(error) => {
            s.store.status(&job.id, "issue_uncertain", Some(error.1))?;
            s.store.audit(&user.sub, "issue", &job.id, "uncertain")?;
            return Err(error);
        }
    };
    let certificate = result["certificate"].as_str();
    let id = result["id"].as_str();
    let outcome = match (id, certificate) {
        (Some(id), Some(pem))
            if uuid::Uuid::parse_str(id).is_ok() && result["status"] == "active" =>
        {
            match crypto::check_certificate(pem, &job.cn, &spki, s.config.cloudflare.validity_days)
            {
                Ok(checked) => {
                    s.store
                        .issued(&job.id, id, pem, &checked.fingerprint, &checked.expires_at)?;
                    let mut fps = s.store.active_fingerprints()?;
                    fps.push(checked.fingerprint);
                    s.cf.update(fps).await
                }
                Err(error) => {
                    s.store.status(&job.id, "manual_review", Some(error.1))?;
                    return Err(error);
                }
            }
        }
        _ => {
            s.store
                .status(&job.id, "issue_uncertain", Some("certificate_response"))?;
            return Err(AppError::remote());
        }
    };
    if let Err(error) = outcome {
        s.store
            .audit(&user.sub, "issue", &job.id, "pending_allow")?;
        return Err(error);
    }
    s.store.status(&job.id, "active", None)?;
    s.store.audit(&user.sub, "issue", &job.id, "active")?;
    let row = s.store.device(&job.id, &user.sub)?;
    Ok(Json(json!({"certificate":row.pem,"device":row})))
}
pub async fn certificate(
    AppState(s): AppState<Arc<State>>,
    Extension(user): Extension<Session>,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let row = s.store.device(&id, &user.sub)?;
    Ok(Json(json!({"certificate":row.pem,"device":row})))
}
pub async fn recover(
    AppState(s): AppState<Arc<State>>,
    Extension(user): Extension<Session>,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let _guard = s.writes.try_lock().map_err(|_| AppError::busy())?;
    let row = s.store.device(&id, &user.sub)?;
    if !["issuing", "issue_uncertain"].contains(&row.status.as_str()) {
        return Err(AppError::conflict("state", "设备状态已变化，请刷新。"));
    }
    let certificates = s.cf.list("active").await?;
    let matches = certificates
        .iter()
        .filter(|c| c["common_name"] == row.cn)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AppError::conflict(
            "manual_review",
            "没有找到唯一签发结果，请稍后核对或联系管理员，不要重复签发。",
        ));
    }
    let found = matches[0];
    let pem = found["certificate"].as_str().ok_or_else(AppError::remote)?;
    let cf_id = found["id"]
        .as_str()
        .filter(|id| uuid::Uuid::parse_str(id).is_ok())
        .ok_or_else(AppError::remote)?;
    let checked = crypto::check_certificate(
        pem,
        &row.cn,
        &row.spki_hash,
        s.config.cloudflare.validity_days,
    )?;
    s.store
        .issued(&id, cf_id, pem, &checked.fingerprint, &checked.expires_at)?;
    let mut fps = s.store.active_fingerprints()?;
    fps.push(checked.fingerprint);
    s.cf.update(fps).await?;
    s.store.status(&id, "active", None)?;
    s.store.audit(&user.sub, "recover", &id, "active")?;
    Ok(Json(json!({"ok":true})))
}
pub async fn retry(
    AppState(s): AppState<Arc<State>>,
    Extension(user): Extension<Session>,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let _guard = s.writes.try_lock().map_err(|_| AppError::busy())?;
    let row = s.store.device(&id, &user.sub)?;
    if row.status != "issued_pending_allow" {
        return Err(AppError::conflict("state", "设备状态已变化，请刷新。"));
    }
    let id_remote = row.cf_id.as_deref().ok_or_else(AppError::internal)?;
    let cert = s.cf.certificate(id_remote).await?;
    if cert["status"] != "active" {
        return Err(AppError::conflict(
            "certificate_inactive",
            "远端证书已失效，不能开通。",
        ));
    }
    let checked = crypto::check_certificate(
        cert["certificate"].as_str().ok_or_else(AppError::remote)?,
        &row.cn,
        &row.spki_hash,
        s.config.cloudflare.validity_days,
    )?;
    if row.fingerprint.as_deref() != Some(&checked.fingerprint) {
        return Err(AppError::conflict(
            "certificate_mismatch",
            "远端证书与原记录不一致。",
        ));
    }
    let mut fps = s.store.active_fingerprints()?;
    fps.push(checked.fingerprint);
    s.cf.update(fps).await?;
    s.store.status(&id, "active", None)?;
    s.store.audit(&user.sub, "retry", &id, "active")?;
    Ok(Json(json!({"ok":true})))
}
pub async fn revoke(
    AppState(s): AppState<Arc<State>>,
    Extension(user): Extension<Session>,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let _guard = s.writes.try_lock().map_err(|_| AppError::busy())?;
    let row = s.store.device(&id, &user.sub)?;
    if row.status == "revoked" {
        return Ok(Json(json!({"ok":true})));
    }
    let remote_id = row
        .cf_id
        .as_deref()
        .ok_or_else(|| AppError::conflict("manual_review", "签发结果未确认，需要管理员核对。"))?;
    let fingerprint = row.fingerprint.ok_or_else(AppError::internal)?;
    s.store.status(&id, "revocation_pending", None)?;
    let fps = s
        .store
        .active_fingerprints()?
        .into_iter()
        .filter(|f| f != &fingerprint)
        .collect();
    s.cf.update(fps).await?;
    s.store.status(&id, "blocked_pending_revoke", None)?;
    s.store.audit(&user.sub, "revoke", &id, "blocked")?;
    let remote = s.cf.certificate(remote_id).await?;
    if remote["status"] != "revoked" && remote["status"] != "pending_revocation" {
        let result =
            s.cf.request(
                &format!("/client_certificates/{remote_id}"),
                Method::DELETE,
                None,
            )
            .await?;
        if result["status"] != "revoked" && result["status"] != "pending_revocation" {
            return Err(AppError::remote());
        }
    }
    s.store.status(&id, "revoked", None)?;
    s.store.audit(&user.sub, "revoke", &id, "revoked")?;
    Ok(Json(json!({"ok":true})))
}
