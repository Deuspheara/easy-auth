use crate::browser::boundary;
use crate::handlers::{account::*, email::*, health::*, passwords::*, recovery::*, sessions::*};
use crate::{Auth, BrowserConfig, openapi};
use axum::{
    Json, Router,
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
};

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) auth: Auth,
    pub(crate) browser: BrowserConfig,
}

pub fn router(auth: Auth, browser: BrowserConfig) -> Router {
    configured_router(auth, browser, openapi())
}

pub(crate) fn configured_router(
    auth: Auth,
    browser: BrowserConfig,
    spec: utoipa::openapi::OpenApi,
) -> Router {
    let pages = crate::pages::routes(auth.passwords_enabled(), &spec);
    let state = AppState { auth, browser };
    Router::new()
        .route("/healthz", get(health))
        .route(
            "/openapi.json",
            get(move || {
                let spec = spec.clone();
                async move { Json(spec) }
            }),
        )
        .route("/readyz", get(ready))
        .route("/v1/email/start", post(start))
        .route("/v1/email/finish", post(finish))
        .route("/v1/password/enroll", post(enroll_password))
        .route("/v1/password/login", post(password_login))
        .route("/v1/password/reset/start", post(start_password_reset))
        .route("/v1/password/reset/finish", post(finish_password_reset))
        .route("/v1/account/email/start", post(start_email_change))
        .route("/v1/account/email/confirm", post(confirm_email_change))
        .route("/v1/account/delete/start", post(start_account_deletion))
        .route("/v1/account/delete/finish", post(finish_account_deletion))
        .route("/v1/session", get(session))
        .route(
            "/v1/account/providers",
            get(crate::handlers::providers::linked_providers),
        )
        .route("/v1/sessions", get(list_sessions))
        .route("/v1/sessions/revoke", post(revoke_session))
        .route("/v1/sessions/revoke-all", post(revoke_all_sessions))
        .route("/v1/logout", post(logout))
        .merge(pages)
        .layer(DefaultBodyLimit::max(8192))
        .layer(middleware::from_fn_with_state(state.clone(), boundary))
        .with_state(state)
}
