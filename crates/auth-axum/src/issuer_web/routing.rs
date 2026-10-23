use super::{IssuerWebServices, issuer_web_openapi, metadata, token};
use crate::{
    Auth, BrowserConfig,
    browser::{boundary, client_token_boundary},
    router::{AppState, configured_router},
};
use auth_core::{Error, Result};
use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
};

const MAX_TOKEN_BODY_BYTES: usize = 8192;
#[derive(Clone)]
pub(super) struct WebState {
    pub services: IssuerWebServices,
}
/// Explicit engineering composition. The token POST requires `ConnectInfo<SocketAddr>`
/// from the actual server transport; no forwarding-header or loopback fallback.
pub fn experimental_issuer_web_router(
    auth: Auth,
    browser: BrowserConfig,
    services: IssuerWebServices,
) -> Result<Router> {
    compose(auth, browser, services, issuer_web_openapi())
}
pub(super) fn compose(
    auth: Auth,
    browser: BrowserConfig,
    services: IssuerWebServices,
    contract: utoipa::openapi::OpenApi,
) -> Result<Router> {
    if auth.realm() != services.tokens.authority().realm()
        || browser.origin() != services.metadata.origin()
    {
        return Err(Error::InvalidInput);
    }
    let base = AppState {
        auth: auth.clone(),
        browser: browser.clone(),
    };
    let router = configured_router(auth.clone(), browser.clone(), contract);
    let router =
        crate::issuer_consent::attach(router, auth, browser, services.authorization.clone())?;
    let state = WebState { services };
    let documents = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(metadata::discovery),
        )
        .route("/oidc/jwks", get(metadata::jwks))
        .layer(middleware::from_fn_with_state(base.clone(), boundary))
        .with_state(state.clone());
    let token = Router::new()
        .route("/oidc/token", post(token::exchange))
        .layer(DefaultBodyLimit::max(MAX_TOKEN_BODY_BYTES))
        .layer(middleware::from_fn_with_state(base, client_token_boundary))
        .with_state(state);
    Ok(router.merge(documents).merge(token))
}
