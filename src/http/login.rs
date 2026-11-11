use crate::{
    auth,
    error::{AppError, Result},
    state,
};
use axum::{
    extract::State,
    http::header,
    response::{IntoResponse, Redirect, Response},
};
use std::sync::Arc;

pub(super) async fn login(State(s): State<Arc<state::State>>) -> Result<Response> {
    let (url, cookie) = s.auth.begin().await?;
    let mut response = Redirect::temporary(&url).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        cookie.parse().map_err(|_| AppError::internal())?,
    );
    Ok(response)
}
pub(super) async fn callback(
    State(s): State<Arc<state::State>>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<auth::Callback>,
) -> Result<Response> {
    let (user, cookie) = s.auth.finish(&headers, query).await?;
    s.store.audit(&user.sub, "login", "", "success")?;
    let mut response = Redirect::to("/").into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        cookie.parse().map_err(|_| AppError::internal())?,
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        auth::set_cookie(auth::LOGIN, "", 0)
            .parse()
            .map_err(|_| AppError::internal())?,
    );
    Ok(response)
}
