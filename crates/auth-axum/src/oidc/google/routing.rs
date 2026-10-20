use super::{GoogleWebServices, callback, deletion, google_web_openapi, pages, signin};
use crate::oidc::cookies::{GOOGLE_DELETION_COOKIES, GOOGLE_SIGN_IN_COOKIES, clear_revoked_proofs};
use crate::{
    Auth, BrowserConfig,
    browser::boundary,
    router::{AppState, configured_router},
};
use auth_core::{Error, Result};
use axum::{
    Router,
    extract::{DefaultBodyLimit, Request, State},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};

pub(super) const CALLBACK_PATH: &str = "/google/callback";
// Includes JSON escaping overhead; the core raw-query bound remains8192bytes.
const MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub(super) struct WebState {
    pub base: AppState,
    pub services: GoogleWebServices,
}

/// Explicit experimental HTTPS Google transport. Real registered-profile and
/// usable lifecycle evidence are still required before ordinary activation.
pub fn experimental_google_web_router(
    auth: Auth,
    browser: BrowserConfig,
    services: GoogleWebServices,
) -> Result<Router> {
    let configuration = services.policy.configuration();
    if auth.realm() != configuration.realm()
        || !browser.origin().starts_with("https://")
        || configuration.redirect() != format!("{}{CALLBACK_PATH}", browser.origin())
    {
        return Err(Error::InvalidInput);
    }
    let base = AppState {
        auth: auth.clone(),
        browser: browser.clone(),
    };
    let routes = Router::new()
        .route("/v1/google/sign-in/start", post(signin::start))
        .route("/v1/google/sign-in/finish", post(signin::finish))
        .route("/v1/google/sign-in/cancel", post(signin::cancel))
        .route("/v1/account/google-delete/start", post(deletion::start))
        .route("/v1/account/google-delete/finish", post(deletion::finish))
        .route("/v1/account/google-delete/cancel", post(deletion::cancel))
        .route(CALLBACK_PATH, get(callback::bridge))
        .merge(pages::routes())
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn_with_state(base.clone(), boundary))
        .with_state(WebState {
            base: base.clone(),
            services,
        });
    Ok(configured_router(auth, browser, google_web_openapi())
        .merge(routes)
        .layer(middleware::from_fn_with_state(base, clear_revoked)))
}
async fn clear_revoked(State(base): State<AppState>, request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    clear_revoked_proofs(
        &mut response,
        &base.browser,
        &[&GOOGLE_SIGN_IN_COOKIES, &GOOGLE_DELETION_COOKIES],
    );
    response
}
