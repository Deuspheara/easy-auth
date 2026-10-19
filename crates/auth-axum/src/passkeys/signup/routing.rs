use super::{handlers, passkey_signup_openapi};
use crate::browser::boundary;
use crate::router::{AppState, configured_router};
use crate::{Auth, BrowserConfig};
use auth_core::{Error, PasskeyEnrollment, PasskeySignIn, PasskeySignup, Result};
use axum::{Router, extract::DefaultBodyLimit, middleware, routing::post};
use std::sync::Arc;
use url::Url;

#[derive(Clone)]
pub(super) struct SignupState {
    pub base: AppState,
    pub signup: Arc<PasskeySignup>,
}

/// Explicit experimental composition; ordinary server activation still requires
/// reviewed stronger-account management/recovery and the remaining M03 evidence.
pub fn experimental_passkey_signup_router(
    auth: Auth,
    browser: BrowserConfig,
    enrollment: Arc<PasskeyEnrollment>,
    sign_in: Arc<PasskeySignIn>,
    signup: Arc<PasskeySignup>,
) -> Result<Router> {
    if auth.realm() != signup.realm()
        || Url::parse(browser.origin())
            .map_err(|_| Error::InvalidInput)?
            .as_str()
            != signup.origin()
    {
        return Err(Error::InvalidInput);
    }
    let enrollment = super::super::routing::enrollment_routes(&auth, &browser, enrollment)?;
    let authentication =
        super::super::authentication::authentication_routes(&auth, &browser, sign_in)?;
    let base = AppState {
        auth: auth.clone(),
        browser: browser.clone(),
    };
    let routes = Router::new()
        .route("/v1/passkeys/signup/start", post(handlers::start))
        .route(
            "/v1/passkeys/signup/registration",
            post(handlers::registration),
        )
        .route("/v1/passkeys/signup/finish", post(handlers::finish))
        .layer(DefaultBodyLimit::max(32 * 1024))
        .layer(middleware::from_fn_with_state(base.clone(), boundary))
        .with_state(SignupState { base, signup });
    Ok(configured_router(auth, browser, passkey_signup_openapi())
        .merge(enrollment)
        .merge(authentication)
        .merge(routes))
}
