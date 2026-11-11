//! OIDC same-origin transport and bounded remote responses; secret-file loading.
use crate::error::{AppError, Result};
use axum::http::HeaderMap;
use secrecy::SecretString;
use zeroize::Zeroizing;

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
#[derive(Clone)]
pub(super) struct OidcHttp {
    pub(super) client: reqwest::Client,
    pub(super) issuer: url::Url,
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
