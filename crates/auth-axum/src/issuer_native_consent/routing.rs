use super::{handlers, issuer_native_consent_openapi, pages};
use crate::{
    Auth, BrowserConfig,
    browser::boundary,
    router::{AppState, configured_router},
};
use auth_core::{Error, IssuerAuthorization, IssuerNativeAuthorization, Result};
use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
};
use std::sync::Arc;

const MAX_NATIVE_CONSENT_BODY_BYTES: usize = 16 * 1024;
#[derive(Clone)]
pub(super) struct WebState {
    pub base: AppState,
    pub authorization: Arc<IssuerNativeAuthorization>,
}
/// Explicit owner confirmation/code delivery. Native token/refresh endpoints and
/// standalone activation are separate; a prompt parameter is not human consent.
pub fn experimental_issuer_native_consent_router(
    auth: Auth,
    browser: BrowserConfig,
    online: Arc<IssuerAuthorization>,
    native: Arc<IssuerNativeAuthorization>,
) -> Result<Router> {
    attach(
        configured_router(
            auth.clone(),
            browser.clone(),
            issuer_native_consent_openapi(),
        ),
        auth,
        browser,
        online,
        native,
    )
}
pub(crate) fn attach(
    router: Router,
    auth: Auth,
    browser: BrowserConfig,
    online: Arc<IssuerAuthorization>,
    native: Arc<IssuerNativeAuthorization>,
) -> Result<Router> {
    attach_with_pages(
        router,
        auth,
        browser,
        online,
        native,
        crate::issuer_consent::page_routes(),
    )
}
pub(crate) fn attach_with_pages(
    router: Router,
    auth: Auth,
    browser: BrowserConfig,
    online: Arc<IssuerAuthorization>,
    native: Arc<IssuerNativeAuthorization>,
    pages: Router,
) -> Result<Router> {
    if online.authority() != native.authority() {
        return Err(Error::InvalidInput);
    }
    // Shared attachment validates realm/HTTPS root and clears the same private
    // operation transport whenever a local session is replaced. Only one consent
    // (online or native) may own these cookies; core independently checks its kind.
    let router = crate::issuer_consent::attach_with_pages(
        router,
        auth.clone(),
        browser.clone(),
        online,
        pages,
    )?;
    let base = AppState { auth, browser };
    let routes = Router::new()
        .route("/oidc/native/authorize", get(pages::authorize))
        .route("/oidc/native/authorize.js", get(pages::script))
        .route("/v1/oidc/native/consent/prepare", post(handlers::prepare))
        .route("/v1/oidc/native/consent/resume", post(handlers::resume))
        .route("/v1/oidc/native/consent/approve", post(handlers::approve))
        .route("/v1/oidc/native/consent/cancel", post(handlers::cancel))
        .layer(DefaultBodyLimit::max(MAX_NATIVE_CONSENT_BODY_BYTES))
        .layer(middleware::from_fn_with_state(base.clone(), boundary))
        .with_state(WebState {
            base,
            authorization: native,
        });
    Ok(router.merge(routes))
}
