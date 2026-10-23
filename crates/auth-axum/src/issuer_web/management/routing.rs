use super::super::{IssuerWebServices, routing};
use super::{handlers, issuer_token_management_openapi};
use crate::{Auth, BrowserConfig, browser::client_token_boundary, router::AppState};
use auth_core::{Error, IssuerTokenManagement, Result};
use axum::{Router, extract::DefaultBodyLimit, middleware, routing::post};
use std::sync::Arc;

const MAX_STATUS_BODY_BYTES: usize = 4096;
#[derive(Clone)]
pub(super) struct ManagementState {
    pub management: Arc<IssuerTokenManagement>,
}
/// Explicit status/revocation extension. Actual socket ConnectInfo remains
/// mandatory; local cookies and forwarding headers confer no authority.
pub fn experimental_issuer_token_management_web_router(
    auth: Auth,
    browser: BrowserConfig,
    services: IssuerWebServices,
    management: Arc<IssuerTokenManagement>,
) -> Result<Router> {
    if management.authority() != services.tokens.authority() {
        return Err(Error::InvalidInput);
    }
    let boundary = AppState {
        auth: auth.clone(),
        browser: browser.clone(),
    };
    let base = routing::compose(auth, browser, services, issuer_token_management_openapi())?;
    let routes = Router::new()
        .route("/oidc/introspect", post(handlers::introspect))
        .route("/oidc/revoke", post(handlers::revoke))
        .layer(DefaultBodyLimit::max(MAX_STATUS_BODY_BYTES))
        .layer(middleware::from_fn_with_state(
            boundary,
            client_token_boundary,
        ))
        .with_state(ManagementState { management });
    Ok(base.merge(routes))
}
