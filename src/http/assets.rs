//! Closed asset allowlist: no runtime filesystem lookup or catch-all asset path.
use crate::state::State;
use axum::{Router, http::header, routing::get};
use std::sync::Arc;

const ASSETS: &[(&str, &[u8], &str)] = &[
    (
        "/",
        include_bytes!("../../web/index.html"),
        "text/html; charset=utf-8",
    ),
    (
        "/assets/css/app.css",
        include_bytes!("../../web/assets/css/app.css"),
        "text/css; charset=utf-8",
    ),
    (
        "/assets/vendor/bulma.min.css",
        include_bytes!("../../web/assets/vendor/bulma.min.css"),
        "text/css; charset=utf-8",
    ),
    (
        "/assets/vendor/forge.min.js",
        include_bytes!("../../web/assets/vendor/forge.min.js"),
        "text/javascript; charset=utf-8",
    ),
    (
        "/assets/js/app.mjs",
        include_bytes!("../../web/assets/js/app.mjs"),
        "text/javascript; charset=utf-8",
    ),
    (
        "/assets/js/api.mjs",
        include_bytes!("../../web/assets/js/api.mjs"),
        "text/javascript; charset=utf-8",
    ),
    (
        "/assets/js/certificates.mjs",
        include_bytes!("../../web/assets/js/certificates.mjs"),
        "text/javascript; charset=utf-8",
    ),
    (
        "/assets/js/devices.mjs",
        include_bytes!("../../web/assets/js/devices.mjs"),
        "text/javascript; charset=utf-8",
    ),
    (
        "/assets/js/install.mjs",
        include_bytes!("../../web/assets/js/install.mjs"),
        "text/javascript; charset=utf-8",
    ),
];

pub(super) fn routes() -> Router<Arc<State>> {
    ASSETS
        .iter()
        .fold(Router::new(), |router, &(path, body, content_type)| {
            router.route(
                path,
                get(move || async move { ([(header::CONTENT_TYPE, content_type)], body) }),
            )
        })
}
