use super::super::{
    cookies::{ACCOUNT_DELETION_COOKIES, SIGN_IN_COOKIES},
    deletion::{self, OidcAccountDeletionServices},
    source::Source,
};
use super::{callback, handlers, oidc_web_openapi, pages};
use crate::{
    Auth, BrowserConfig,
    browser::boundary,
    router::{AppState, configured_router},
};
use auth_core::{
    Error, OAuthTransactions, OidcAccountDeletion, OidcCodeExchange, OidcIdentityPolicy,
    OidcSignIn, Result,
};
use axum::{
    Router,
    extract::{DefaultBodyLimit, Request, State},
    http::header,
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
use std::sync::Arc;

pub(super) const CALLBACK_PATH: &str = "/oidc/callback";

/// One trusted, persisted provider source shared by sign-in and deletion.
/// Provider credentials belong to the protected exchange service, never a browser DTO.
#[derive(Clone)]
pub struct OidcWebServices {
    pub(super) source: Arc<Source>,
    pub(super) sign_in: Arc<OidcSignIn>,
    deletion: Arc<OidcAccountDeletion>,
}
impl OidcWebServices {
    pub fn new(
        policy: OidcIdentityPolicy,
        transactions: Arc<OAuthTransactions>,
        exchange: Arc<OidcCodeExchange>,
        sign_in: Arc<OidcSignIn>,
        deletion: Arc<OidcAccountDeletion>,
    ) -> Result<Self> {
        Ok(Self {
            source: Arc::new(Source::new(policy, transactions, exchange)?),
            sign_in,
            deletion,
        })
    }
}
#[derive(Clone)]
pub(super) struct WebState {
    pub base: AppState,
    pub services: OidcWebServices,
}

/// Explicit supported same-origin OIDC composition. Requires HTTPS and the exact
/// common callback. Existing session cookies require explicit logout before sign-in.
pub fn oidc_web_router(
    auth: Auth,
    browser: BrowserConfig,
    services: OidcWebServices,
) -> Result<Router> {
    let connection = services.source.policy.configuration();
    if auth.realm() != connection.realm()
        || !browser.origin().starts_with("https://")
        || connection.redirect() != format!("{}{CALLBACK_PATH}", browser.origin())
    {
        return Err(Error::InvalidInput);
    }
    let base = AppState {
        auth: auth.clone(),
        browser: browser.clone(),
    };
    let deletion = OidcAccountDeletionServices::from_source(
        services.source.clone(),
        services.deletion.clone(),
    );
    let state = WebState {
        base: base.clone(),
        services,
    };
    let routes = Router::new()
        .route("/v1/oidc/sign-in/start", post(handlers::start))
        .route("/v1/oidc/sign-in/finish", post(handlers::finish))
        .route("/v1/oidc/sign-in/cancel", post(handlers::cancel))
        .route(CALLBACK_PATH, get(callback::bridge))
        .merge(pages::routes())
        .layer(DefaultBodyLimit::max(8192))
        .layer(middleware::from_fn_with_state(base.clone(), boundary))
        .with_state(state);
    Ok(configured_router(auth, browser, oidc_web_openapi())
        .merge(routes)
        .merge(deletion::routes(base.clone(), deletion))
        .layer(middleware::from_fn_with_state(base, clear_revoked_proof)))
}

async fn clear_revoked_proof(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let prefix = format!("{}=;", state.browser.session_name());
    if response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|value| value.to_str().is_ok_and(|value| value.starts_with(&prefix)))
    {
        SIGN_IN_COOKIES.clear(&mut response, &state.browser);
        ACCOUNT_DELETION_COOKIES.clear(&mut response, &state.browser);
    }
    response
}
