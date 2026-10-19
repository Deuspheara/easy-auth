use super::{handlers, passkey_authentication_openapi};
use crate::browser::boundary;
use crate::router::{AppState, configured_router};
use crate::{Auth, BrowserConfig};
use auth_core::{Error, PasskeyEnrollment, PasskeySignIn, Result};
use axum::{Router, extract::DefaultBodyLimit, middleware, routing::post};
use std::sync::Arc;
use url::Url;

#[derive(Clone)]
pub(super) struct AuthenticationState {
    pub base: AppState,
    pub sign_in: Arc<PasskeySignIn>,
}

/// Explicit experimental enrollment + authentication. Ordinary server composition
/// remains gated until stronger-account management/recovery policy is complete.
pub fn experimental_passkey_router(
    auth: Auth,
    browser: BrowserConfig,
    enrollment: Arc<PasskeyEnrollment>,
    sign_in: Arc<PasskeySignIn>,
) -> Result<Router> {
    if auth.realm() != sign_in.realm()
        || Url::parse(browser.origin())
            .map_err(|_| Error::InvalidInput)?
            .as_str()
            != sign_in.origin()
    {
        return Err(Error::InvalidInput);
    }
    let enrollment = super::super::routing::enrollment_routes(&auth, &browser, enrollment)?;
    let base = AppState {
        auth: auth.clone(),
        browser: browser.clone(),
    };
    let routes = Router::new()
        .route("/v1/passkeys/authentication/start", post(handlers::start))
        .route("/v1/passkeys/authentication/finish", post(handlers::finish))
        .layer(DefaultBodyLimit::max(32 * 1024))
        .layer(middleware::from_fn_with_state(base.clone(), boundary))
        .with_state(AuthenticationState { base, sign_in });
    Ok(
        configured_router(auth, browser, passkey_authentication_openapi())
            .merge(enrollment)
            .merge(routes),
    )
}
