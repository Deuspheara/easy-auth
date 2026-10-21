use super::{cookies, delivery, handlers, pages, saml_web_openapi};
use crate::{
    Auth, BrowserConfig,
    browser::{boundary, post_delivery_boundary},
    router::{AppState, configured_router},
};
use auth_core::{
    Error, Result, SamlIdentityPolicy, SamlIdentityRepository, SamlRequestRepository,
    SamlResponseVerifier, SamlSignIn, SamlTransactions, SamlVerificationRepository,
};
use axum::{
    Router,
    extract::{DefaultBodyLimit, Request, State},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
use std::sync::Arc;

pub(super) const ACS_PATH: &str = "/saml/acs";
// Form encoding can expand each byte threefold; core independently enforces its
// encoded SAMLResponse bound. No body field is ever a source/policy selector.
const MAX_DELIVERY_BODY_BYTES: usize = 800 * 1024;

#[derive(Clone)]
pub struct SamlWebServices {
    pub(super) policy: SamlIdentityPolicy,
    pub(super) transactions: Arc<SamlTransactions>,
    pub(super) verifier: Arc<SamlResponseVerifier>,
    pub(super) sign_in: Arc<SamlSignIn>,
}
impl SamlWebServices {
    /// Trusted exact policy; component source snapshots cannot drift apart.
    pub fn new(
        policy: SamlIdentityPolicy,
        requests: Arc<dyn SamlRequestRepository>,
        verification: Arc<dyn SamlVerificationRepository>,
        identities: Arc<dyn SamlIdentityRepository>,
    ) -> Result<Self> {
        let reg = policy.registration().clone();
        Ok(Self {
            policy,
            transactions: Arc::new(SamlTransactions::new(reg.clone(), requests)),
            verifier: Arc::new(SamlResponseVerifier::new(reg, verification)?),
            sign_in: Arc::new(SamlSignIn::new(identities)),
        })
    }
}
#[derive(Clone)]
pub(super) struct WebState {
    pub base: AppState,
    pub services: SamlWebServices,
}
/// Gated engineering composition only; not wired into ordinary server startup.
/// The cross-site ACS renders a handoff page; only same-origin finish grants authority.
pub fn experimental_saml_web_router(
    auth: Auth,
    browser: BrowserConfig,
    services: SamlWebServices,
) -> Result<Router> {
    let reg = services.policy.registration();
    if auth.realm() != reg.realm()
        || !browser.origin().starts_with("https://")
        || reg.acs() != format!("{}{ACS_PATH}", browser.origin())
    {
        return Err(Error::InvalidInput);
    }
    let base = AppState {
        auth: auth.clone(),
        browser: browser.clone(),
    };
    let state = WebState {
        base: base.clone(),
        services,
    };
    let protected = Router::new()
        .route("/v1/saml/sign-in/start", post(handlers::start))
        .route("/v1/saml/sign-in/finish", post(handlers::finish))
        .route("/v1/saml/sign-in/cancel", post(handlers::cancel))
        .route("/saml/sign-in", get(pages::sign_in))
        .route("/saml/sign-in.js", get(pages::sign_in_script))
        .route("/saml/delivery.js", get(pages::delivery_script))
        .route("/saml/metadata", get(handlers::metadata))
        .layer(DefaultBodyLimit::max(MAX_DELIVERY_BODY_BYTES))
        .layer(middleware::from_fn_with_state(base.clone(), boundary));
    let delivery = Router::new()
        .route(ACS_PATH, post(delivery::bridge))
        .layer(DefaultBodyLimit::max(MAX_DELIVERY_BODY_BYTES))
        .layer(middleware::from_fn_with_state(
            base.clone(),
            post_delivery_boundary,
        ));
    Ok(configured_router(auth, browser, saml_web_openapi())
        .merge(protected.merge(delivery).with_state(state))
        .layer(middleware::from_fn_with_state(base, clear_revoked_proofs)))
}
async fn clear_revoked_proofs(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    cookies::clear_if_logged_out(&mut response, &state.browser);
    response
}
