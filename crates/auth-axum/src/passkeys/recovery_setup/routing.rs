use super::{handlers, passkey_recovery_setup_openapi};
use crate::{Auth, BrowserConfig, browser::boundary, router::AppState};
use auth_core::{
    Error, PasskeyEnrollment, PasskeyManagement, PasskeyRecoverySetup, PasskeySignIn,
    PasskeySignup, Result,
};
use axum::{Router, extract::DefaultBodyLimit, middleware, routing::post};
use std::sync::Arc;
use url::Url;

#[derive(Clone)]
pub(super) struct RecoverySetupState {
    pub setup: Arc<PasskeyRecoverySetup>,
    pub browser: BrowserConfig,
}

/// Explicit configuration only. No recovery authentication or ordinary activation.
pub fn experimental_passkey_recovery_setup_router(
    auth: Auth,
    browser: BrowserConfig,
    enrollment: Arc<PasskeyEnrollment>,
    sign_in: Arc<PasskeySignIn>,
    signup: Arc<PasskeySignup>,
    management: Arc<PasskeyManagement>,
    setup: Arc<PasskeyRecoverySetup>,
) -> Result<Router> {
    let routes = setup_routes(&auth, &browser, setup)?;
    Ok(super::super::management::configured_management_router(
        auth,
        browser,
        enrollment,
        sign_in,
        signup,
        management,
        passkey_recovery_setup_openapi(),
    )?
    .merge(routes))
}

pub(in crate::passkeys) fn setup_routes(
    auth: &Auth,
    browser: &BrowserConfig,
    setup: Arc<PasskeyRecoverySetup>,
) -> Result<Router> {
    if auth.realm() != setup.realm()
        || Url::parse(browser.origin())
            .map_err(|_| Error::InvalidInput)?
            .as_str()
            != setup.origin()
    {
        return Err(Error::InvalidInput);
    }
    let base = AppState {
        auth: auth.clone(),
        browser: browser.clone(),
    };
    let routes = Router::new()
        .route(
            "/v1/passkeys/recovery/code/prepare",
            post(handlers::prepare),
        )
        .route(
            "/v1/passkeys/recovery/code/confirm",
            post(handlers::confirm),
        )
        .layer(DefaultBodyLimit::max(8192))
        .layer(middleware::from_fn_with_state(base, boundary))
        .with_state(RecoverySetupState {
            setup,
            browser: browser.clone(),
        });
    Ok(routes)
}
