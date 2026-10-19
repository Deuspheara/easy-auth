use super::{handlers, passkey_enrollment_openapi};
use crate::browser::boundary;
use crate::router::{AppState, configured_router};
use crate::{Auth, BrowserConfig};
use auth_core::{Error, PasskeyEnrollment, Result};
use axum::{Router, extract::DefaultBodyLimit, middleware, routing::post};
use std::sync::Arc;
use url::Url;

#[derive(Clone)]
pub(super) struct PasskeyState {
    pub(super) enrollment: Arc<PasskeyEnrollment>,
    pub(super) browser: BrowserConfig,
}

/// Explicit experimental composition only: registration does not yet enable sign-in
/// or stronger-account recovery policy. The ordinary router/server never calls this.
pub fn experimental_passkey_enrollment_router(
    auth: Auth,
    browser: BrowserConfig,
    enrollment: Arc<PasskeyEnrollment>,
) -> Result<Router> {
    let routes = enrollment_routes(&auth, &browser, enrollment)?;
    Ok(configured_router(auth, browser, passkey_enrollment_openapi()).merge(routes))
}

pub(super) fn enrollment_routes(
    auth: &Auth,
    browser: &BrowserConfig,
    enrollment: Arc<PasskeyEnrollment>,
) -> Result<Router> {
    if auth.realm() != enrollment.realm()
        || Url::parse(browser.origin())
            .map_err(|_| Error::InvalidInput)?
            .as_str()
            != enrollment.origin()
    {
        return Err(Error::InvalidInput);
    }
    let boundary_state = AppState {
        auth: auth.clone(),
        browser: browser.clone(),
    };
    let state = PasskeyState {
        enrollment,
        browser: browser.clone(),
    };
    Ok(Router::new()
        .route("/v1/passkeys/enrollment/start", post(handlers::start))
        .route("/v1/passkeys/enrollment/finish", post(handlers::finish))
        .layer(DefaultBodyLimit::max(32 * 1024))
        .layer(middleware::from_fn_with_state(boundary_state, boundary))
        .with_state(state))
}
