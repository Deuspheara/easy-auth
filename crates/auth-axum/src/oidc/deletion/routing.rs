use super::super::{cookies::ACCOUNT_DELETION_COOKIES as COOKIES, source::Source};
use super::{handlers, oidc_account_deletion_openapi};
use crate::{
    Auth, BrowserConfig,
    browser::boundary,
    router::{AppState, configured_router},
};
use auth_core::{
    Error, OAuthTransactions, OidcAccountDeletion, OidcCodeExchange, OidcIdentityPolicy, Result,
};
use axum::{
    Router,
    extract::{DefaultBodyLimit, Request, State},
    http::header,
    middleware::{self, Next},
    response::Response,
    routing::post,
};
use std::sync::Arc;

pub(super) const CALLBACK_PATH: &str = "/oidc/account-delete/callback";

/// Trusted services for one fixed provider configuration. Construct with the
/// persisted policy/revision; no browser-supplied owner or connection is accepted.
#[derive(Clone)]
pub struct OidcAccountDeletionServices {
    pub(super) source: Arc<Source>,
    pub(super) deletion: Arc<OidcAccountDeletion>,
}
impl OidcAccountDeletionServices {
    pub fn new(
        policy: OidcIdentityPolicy,
        transactions: Arc<OAuthTransactions>,
        exchange: Arc<OidcCodeExchange>,
        deletion: Arc<OidcAccountDeletion>,
    ) -> Result<Self> {
        Ok(Self {
            source: Arc::new(Source::new(policy, transactions, exchange)?),
            deletion,
        })
    }
}
#[derive(Clone)]
pub(super) struct DeletionState {
    pub base: AppState,
    pub services: OidcAccountDeletionServices,
}

/// Opt-in provider deletion only. Ordinary provider sign-in remains a separate
/// composition. HTTPS and the exact dedicated callback are required even in dev.
pub fn experimental_oidc_account_deletion_router(
    auth: Auth,
    browser: BrowserConfig,
    services: OidcAccountDeletionServices,
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
    let state = DeletionState {
        base: base.clone(),
        services,
    };
    let routes = Router::new()
        .route("/v1/account/provider-delete/start", post(handlers::start))
        .route("/v1/account/provider-delete/finish", post(handlers::finish))
        .route("/v1/account/provider-delete/cancel", post(handlers::cancel))
        .merge(super::pages::routes())
        .layer(DefaultBodyLimit::max(8192))
        .layer(middleware::from_fn_with_state(base.clone(), boundary))
        .with_state(state);
    Ok(
        configured_router(auth, browser, oidc_account_deletion_openapi())
            .merge(routes)
            .layer(middleware::from_fn_with_state(base, clear_revoked_proof)),
    )
}

// Only this opt-in composition extends logout/revocation cookie hygiene. The
// database binding already denies proof after its initiating session is revoked.
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
        COOKIES.clear(&mut response, &state.browser);
    }
    response
}
