use super::{AppleWebServices, apple_web_openapi, delivery, operation, pages, signin};
use crate::{
    Auth, BrowserConfig,
    browser::{boundary, post_delivery_boundary},
    oidc::cookies::{APPLE_SIGN_IN_COOKIES, clear_revoked_proofs},
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

pub(super) const CALLBACK_PATH: &str = "/apple/callback";
// Core still caps the actual raw form at32KiB; JSON escaping can expand it.
const MAX_FINISH_BODY_BYTES: usize = 192 * 1024;
const MAX_DELIVERY_BODY_BYTES: usize = 32 * 1024;

#[derive(Clone)]
pub(super) struct WebState {
    pub base: AppState,
    pub services: AppleWebServices,
}

/// Explicit HTTPS experimental adapter; never ordinary Apple activation.
pub fn experimental_apple_web_router(
    auth: Auth,
    browser: BrowserConfig,
    services: AppleWebServices,
) -> Result<Router> {
    let base = AppState {
        auth: auth.clone(),
        browser: browser.clone(),
    };
    let routes = routes(base.clone(), services)?;
    Ok(configured_router(auth, browser, apple_web_openapi())
        .merge(routes)
        .layer(middleware::from_fn_with_state(base, clear_revoked)))
}

pub(in crate::oidc) fn routes(base: AppState, services: AppleWebServices) -> Result<Router> {
    let configuration = services.policy.configuration();
    if base.auth.realm() != configuration.realm()
        || !base.browser.origin().starts_with("https://")
        || configuration.redirect() != format!("{}{CALLBACK_PATH}", base.browser.origin())
    {
        return Err(Error::InvalidInput);
    }
    let protected = Router::new()
        .route("/v1/apple/return-operation", post(operation::operation))
        .route("/v1/apple/sign-in/start", post(signin::start))
        .route("/v1/apple/sign-in/finish", post(signin::finish))
        .route("/v1/apple/sign-in/cancel", post(signin::cancel))
        .route("/apple/sign-in", get(pages::sign_in))
        .route("/apple/client.js", get(pages::script))
        .layer(DefaultBodyLimit::max(MAX_FINISH_BODY_BYTES))
        .layer(middleware::from_fn_with_state(base.clone(), boundary));
    let delivery = Router::new()
        .route(CALLBACK_PATH, post(delivery::bridge))
        .layer(DefaultBodyLimit::max(MAX_DELIVERY_BODY_BYTES))
        .layer(middleware::from_fn_with_state(
            base.clone(),
            post_delivery_boundary,
        ));
    Ok(protected
        .merge(delivery)
        .with_state(WebState { base, services }))
}

async fn clear_revoked(State(base): State<AppState>, request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    clear_revoked_proofs(&mut response, &base.browser, &[&APPLE_SIGN_IN_COOKIES]);
    response
}
