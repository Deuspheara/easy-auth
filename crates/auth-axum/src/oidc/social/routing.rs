use super::{
    SocialLinkingSelected, SocialWebServices, apple, google, pages, social_web_openapi, unlink,
};
use crate::{
    Auth, BrowserConfig,
    browser::boundary,
    oidc::{
        self,
        cookies::{
            APPLE_LINK_COOKIES, APPLE_SIGN_IN_COOKIES, GOOGLE_DELETION_COOKIES,
            GOOGLE_LINK_COOKIES, GOOGLE_SIGN_IN_COOKIES, clear_revoked_proofs,
        },
    },
    router::{AppState, configured_router},
};
use auth_core::Result;
use axum::{
    Extension, Router,
    extract::{DefaultBodyLimit, Request, State},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};

#[derive(Clone)]
pub(super) struct WebState {
    pub base: AppState,
    pub services: SocialWebServices,
}

/// Explicit experimental Google/Apple sign-in and owner-bound identity management.
/// This builder neither activates ordinary providers nor implies interoperability.
pub fn experimental_social_web_router(
    auth: Auth,
    browser: BrowserConfig,
    services: SocialWebServices,
) -> Result<Router> {
    let base = AppState {
        auth: auth.clone(),
        browser: browser.clone(),
    };
    let google_routes = oidc::google::routes(base.clone(), services.google.clone())?
        .layer(Extension(SocialLinkingSelected));
    let apple_routes = oidc::apple::routes(base.clone(), services.apple.clone())?
        .layer(Extension(SocialLinkingSelected));
    let management = Router::new()
        .route("/v1/account/google-link/start", post(google::start))
        .route("/v1/account/google-link/finish", post(google::finish))
        .route("/v1/account/google-link/cancel", post(google::cancel))
        .route("/v1/account/apple-link/start", post(apple::start))
        .route("/v1/account/apple-link/finish", post(apple::finish))
        .route("/v1/account/apple-link/cancel", post(apple::cancel))
        .route("/v1/account/providers/oidc/unlink", post(unlink::unlink))
        .route("/social/accounts", get(pages::accounts))
        .route("/social/accounts.js", get(pages::accounts_script))
        .route("/social/google-return.js", get(pages::return_script))
        // Same bound as Apple's existing escaped JSON completion. Core raw input
        // bounds still apply separately for each provider profile.
        .layer(DefaultBodyLimit::max(192 * 1024))
        .layer(middleware::from_fn_with_state(base.clone(), boundary))
        .with_state(WebState {
            base: base.clone(),
            services,
        });
    Ok(configured_router(auth, browser, social_web_openapi())
        .merge(google_routes)
        .merge(apple_routes)
        .merge(management)
        .layer(middleware::from_fn_with_state(base, clear_revoked)))
}
async fn clear_revoked(State(base): State<AppState>, request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    clear_revoked_proofs(
        &mut response,
        &base.browser,
        &[
            &GOOGLE_SIGN_IN_COOKIES,
            &GOOGLE_DELETION_COOKIES,
            &APPLE_SIGN_IN_COOKIES,
            &GOOGLE_LINK_COOKIES,
            &APPLE_LINK_COOKIES,
        ],
    );
    response
}
