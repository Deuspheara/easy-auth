use super::{
    cookies, deletion, delivery, handlers, operation, pages, saml_account_deletion_web_openapi,
    saml_web_openapi, services::SamlWebServices,
};
use crate::{
    Auth, BrowserConfig,
    browser::{boundary, post_delivery_boundary},
    router::{AppState, configured_router},
};
use auth_core::{Error, Result};
use axum::{
    Router,
    extract::{DefaultBodyLimit, Request, State},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};

pub(super) const ACS_PATH: &str = "/saml/acs";
// Form encoding can expand each byte threefold; core independently enforces its
// encoded SAMLResponse bound. No body field is ever a source/policy selector.
const MAX_DELIVERY_BODY_BYTES: usize = 800 * 1024;

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
    let deletion_enabled = services.deletion.is_some();
    let state = WebState {
        base: base.clone(),
        services,
    };
    let mut protected = Router::new()
        .route("/v1/saml/operation", post(operation::select))
        .route("/v1/saml/sign-in/start", post(handlers::start))
        .route("/v1/saml/sign-in/finish", post(handlers::finish))
        .route("/v1/saml/sign-in/cancel", post(handlers::cancel))
        .route("/saml/sign-in", get(pages::sign_in))
        .route("/saml/sign-in.js", get(pages::sign_in_script))
        .route("/saml/delivery.js", get(pages::delivery_script))
        .route("/saml/metadata", get(handlers::metadata));
    if deletion_enabled {
        protected = protected.merge(deletion::routes());
    }
    let protected = protected
        .layer(DefaultBodyLimit::max(MAX_DELIVERY_BODY_BYTES))
        .layer(middleware::from_fn_with_state(base.clone(), boundary));
    let delivery = Router::new()
        .route(ACS_PATH, post(delivery::bridge))
        .layer(DefaultBodyLimit::max(MAX_DELIVERY_BODY_BYTES))
        .layer(middleware::from_fn_with_state(
            base.clone(),
            post_delivery_boundary,
        ));
    let api = if deletion_enabled {
        saml_account_deletion_web_openapi()
    } else {
        saml_web_openapi()
    };
    Ok(configured_router(auth, browser, api)
        .merge(protected.merge(delivery).with_state(state))
        .layer(middleware::from_fn_with_state(
            (base.browser, deletion_enabled),
            clear_revoked_proofs,
        )))
}
async fn clear_revoked_proofs(
    State((browser, deletion)): State<(BrowserConfig, bool)>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    cookies::clear_if_logged_out(&mut response, &browser, deletion);
    response
}
