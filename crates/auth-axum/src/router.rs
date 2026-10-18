use crate::browser::boundary;
use crate::handlers::{account::*, email::*, health::*, passwords::*, recovery::*, sessions::*};
use crate::{Auth, BrowserConfig, openapi};
use axum::{
    Json, Router,
    extract::DefaultBodyLimit,
    http::header,
    middleware,
    response::Html,
    routing::{get, post},
};

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) auth: Auth,
    pub(crate) browser: BrowserConfig,
}

pub fn router(auth: Auth, browser: BrowserConfig) -> Router {
    let state = AppState { auth, browser };
    Router::new()
        .route("/healthz", get(health))
        .route("/openapi.json", get(|| async { Json(openapi()) }))
        .route("/readyz", get(ready))
        .route("/v1/email/start", post(start))
        .route("/v1/email/finish", post(finish))
        .route("/v1/password/enroll", post(enroll_password))
        .route("/v1/password/login", post(password_login))
        .route("/v1/password/reset/start", post(start_password_reset))
        .route("/v1/password/reset/finish", post(finish_password_reset))
        .route(
            "/reset",
            get(|| async { Html(include_str!("pages/reset.html")) }),
        )
        .route(
            "/reset.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("pages/reset.js"),
                )
            }),
        )
        .route("/v1/account/email/start", post(start_email_change))
        .route("/v1/account/email/confirm", post(confirm_email_change))
        .route("/v1/account/delete/start", post(start_account_deletion))
        .route("/v1/account/delete/finish", post(finish_account_deletion))
        .route(
            "/email-change",
            get(|| async { Html(include_str!("pages/email-change.html")) }),
        )
        .route(
            "/account-delete",
            get(|| async { Html(include_str!("pages/account-delete.html")) }),
        )
        .route(
            "/account-action.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("pages/account-action.js"),
                )
            }),
        )
        .route("/v1/session", get(session))
        .route("/v1/sessions", get(list_sessions))
        .route("/v1/sessions/revoke", post(revoke_session))
        .route("/v1/sessions/revoke-all", post(revoke_all_sessions))
        .route("/v1/logout", post(logout))
        .route(
            "/",
            get(|| async { Html(include_str!("pages/client.html")) }),
        )
        .route(
            "/client.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("pages/client.js"),
                )
            }),
        )
        .layer(DefaultBodyLimit::max(8192))
        .layer(middleware::from_fn_with_state(state.clone(), boundary))
        .with_state(state)
}
