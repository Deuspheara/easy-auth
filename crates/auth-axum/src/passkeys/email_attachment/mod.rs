mod handlers;

use crate::{Auth, BrowserConfig, browser::boundary, router::AppState};
use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::header,
    middleware,
    routing::{get, post},
};
use utoipa::OpenApi;

pub(super) fn routes(auth: &Auth, browser: &BrowserConfig) -> Router {
    let state = AppState {
        auth: auth.clone(),
        browser: browser.clone(),
    };
    Router::new()
        .route("/v1/account/email/attachment/start", post(handlers::start))
        .route(
            "/v1/account/email/attachment/finish",
            post(handlers::finish),
        )
        .route(
            "/email-attach",
            get(|| async { crate::pages::document(include_str!("../../pages/email-attach.html")) }),
        )
        .route(
            "/email-attach.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../../pages/email-attach.js"),
                )
            }),
        )
        .layer(DefaultBodyLimit::max(8192))
        .layer(middleware::from_fn_with_state(state.clone(), boundary))
        .with_state(state)
}

use handlers::{__path_finish, __path_start};
#[derive(OpenApi)]
#[openapi(paths(start, finish))]
struct AttachmentApi;

pub(super) fn extend(api: &mut utoipa::openapi::OpenApi) {
    api.merge(AttachmentApi::openapi());
}
