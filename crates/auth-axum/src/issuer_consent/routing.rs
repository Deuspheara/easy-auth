use super::{cookies, handlers, issuer_consent_openapi, pages};
use crate::{
    Auth, BrowserConfig,
    browser::boundary,
    router::{AppState, configured_router},
};
use auth_core::{Error, IssuerAuthorization, Result};
use axum::{
    Router,
    extract::{DefaultBodyLimit, Request, State},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
use std::sync::Arc;

const MAX_CONSENT_BODY_BYTES: usize = 16 * 1024;
#[derive(Clone)]
pub(super) struct WebState {
    pub base: AppState,
    pub authorization: Arc<IssuerAuthorization>,
}
/// Explicit HTTPS consent/code delivery only. No token endpoint or ordinary
/// standalone issuer activation accompanies this experimental composition.
pub fn experimental_issuer_consent_router(
    auth: Auth,
    browser: BrowserConfig,
    authorization: Arc<IssuerAuthorization>,
) -> Result<Router> {
    attach(
        configured_router(auth.clone(), browser.clone(), issuer_consent_openapi()),
        auth,
        browser,
        authorization,
    )
}

pub(crate) fn attach(
    router: Router,
    auth: Auth,
    browser: BrowserConfig,
    authorization: Arc<IssuerAuthorization>,
) -> Result<Router> {
    let pages = Router::new()
        .route("/oidc/authorize", get(pages::authorize))
        .route("/oidc/authorize.js", get(pages::script));
    attach_with_pages(router, auth, browser, authorization, pages)
}

pub(crate) fn attach_with_pages(
    router: Router,
    auth: Auth,
    browser: BrowserConfig,
    authorization: Arc<IssuerAuthorization>,
    pages: Router,
) -> Result<Router> {
    let authority = authorization.authority();
    if auth.realm() != authority.realm()
        || !browser.origin().starts_with("https://")
        || ![
            browser.origin().to_owned(),
            format!("{}/", browser.origin()),
        ]
        .contains(&authority.issuer().to_owned())
    {
        return Err(Error::InvalidInput);
    }
    let base = AppState {
        auth: auth.clone(),
        browser: browser.clone(),
    };
    let routes = Router::new()
        .route("/v1/oidc/consent/prepare", post(handlers::prepare))
        .route("/v1/oidc/consent/resume", post(handlers::resume))
        .route("/v1/oidc/consent/approve", post(handlers::approve))
        .route("/v1/oidc/consent/cancel", post(handlers::cancel))
        .with_state(WebState {
            base: base.clone(),
            authorization,
        })
        .merge(pages)
        .layer(DefaultBodyLimit::max(MAX_CONSENT_BODY_BYTES))
        .layer(middleware::from_fn_with_state(base, boundary));
    Ok(router.merge(routes).layer(middleware::from_fn_with_state(
        browser,
        clear_changed_session,
    )))
}
async fn clear_changed_session(
    State(browser): State<BrowserConfig>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    cookies::clear_on_session_change(&mut response, &browser);
    response
}
