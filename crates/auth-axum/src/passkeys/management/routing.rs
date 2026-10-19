use super::{handlers, passkey_management_openapi};
use crate::{
    Auth, BrowserConfig,
    browser::boundary,
    router::{AppState, configured_router},
};
use auth_core::{
    Error, PasskeyEnrollment, PasskeyManagement, PasskeySignIn, PasskeySignup, Result,
};
use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
};
use std::sync::Arc;
use url::Url;

#[derive(Clone)]
pub(super) struct ManagementState {
    pub management: Arc<PasskeyManagement>,
    pub browser: BrowserConfig,
}

/// Explicit experimental management composition. Recovery and ordinary activation remain gated.
pub fn experimental_passkey_management_router(
    auth: Auth,
    browser: BrowserConfig,
    enrollment: Arc<PasskeyEnrollment>,
    sign_in: Arc<PasskeySignIn>,
    signup: Arc<PasskeySignup>,
    management: Arc<PasskeyManagement>,
) -> Result<Router> {
    configured_management_router(
        auth,
        browser,
        enrollment,
        sign_in,
        signup,
        management,
        passkey_management_openapi(),
    )
}

pub(in crate::passkeys) fn configured_management_router(
    auth: Auth,
    browser: BrowserConfig,
    enrollment: Arc<PasskeyEnrollment>,
    sign_in: Arc<PasskeySignIn>,
    signup: Arc<PasskeySignup>,
    management: Arc<PasskeyManagement>,
    document: utoipa::openapi::OpenApi,
) -> Result<Router> {
    if auth.realm() != management.realm()
        || Url::parse(browser.origin())
            .map_err(|_| Error::InvalidInput)?
            .as_str()
            != management.origin()
    {
        return Err(Error::InvalidInput);
    }
    let enrollment = super::super::routing::enrollment_routes(&auth, &browser, enrollment)?;
    let authentication =
        super::super::authentication::authentication_routes(&auth, &browser, sign_in)?;
    let signup = super::super::signup::signup_routes(&auth, &browser, signup)?;
    let attachment = super::super::email_attachment::routes(&auth, &browser);
    let base = AppState {
        auth: auth.clone(),
        browser: browser.clone(),
    };
    let routes = Router::new()
        .route("/v1/passkeys", get(handlers::list))
        .route("/v1/passkeys/rename", post(handlers::rename))
        .route("/v1/passkeys/remove", post(handlers::remove))
        .layer(DefaultBodyLimit::max(8192))
        .layer(middleware::from_fn_with_state(base, boundary))
        .with_state(ManagementState {
            management,
            browser: browser.clone(),
        });
    Ok(configured_router(auth, browser, document)
        .merge(enrollment)
        .merge(authentication)
        .merge(signup)
        .merge(attachment)
        .merge(routes))
}
