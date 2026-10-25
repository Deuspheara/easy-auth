use super::super::{management, routing};
use super::{
    IssuerNativeWebServices, authorize, issuer_native_web_openapi, metadata, revocation, token,
};
use crate::{
    Auth, BrowserConfig,
    browser::{boundary, client_token_boundary},
    router::AppState,
};
use auth_core::Result;
use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
};

const MAX_NATIVE_TOKEN_BODY_BYTES: usize = 8192;
const MAX_NATIVE_STATUS_BODY_BYTES: usize = 4096;

pub fn experimental_issuer_native_web_router(
    auth: Auth,
    browser: BrowserConfig,
    services: IssuerNativeWebServices,
) -> Result<Router> {
    let base = AppState {
        auth: auth.clone(),
        browser: browser.clone(),
    };
    let contract = if services.introspection.is_some() {
        super::issuer_native_consumer_openapi()
    } else {
        issuer_native_web_openapi()
    };
    #[cfg(any(feature = "oidc-web", feature = "saml-web"))]
    let contract = services.providers.contract(contract);
    let router = routing::root(&auth, &browser, &services.base, contract)?;
    let pages = Router::new()
        .route("/oidc/authorize", get(authorize::authorize))
        .route(
            "/oidc/authorize.js",
            get(crate::issuer_consent::consent_script),
        );
    let router = crate::issuer_native_consent::attach_with_pages(
        router,
        auth.clone(),
        browser.clone(),
        services.base.authorization.clone(),
        services.consent.clone(),
        pages,
    )?;
    let documents = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(metadata::discovery),
        )
        .with_state(services.clone())
        .merge(
            Router::new()
                .route("/oidc/jwks", get(super::super::metadata::jwks))
                .with_state(routing::WebState {
                    services: services.base.clone(),
                }),
        )
        .layer(middleware::from_fn_with_state(base.clone(), boundary));
    let tokens = Router::new()
        .route("/oidc/token", post(token::exchange))
        .layer(DefaultBodyLimit::max(MAX_NATIVE_TOKEN_BODY_BYTES))
        .with_state(services.clone());
    let consumer = match services.introspection.clone() {
        Some(service) => Router::new()
            .route(
                "/oidc/native/introspect",
                post(super::introspection::inspect),
            )
            .with_state(service),
        None => Router::new(),
    };
    let status = Router::new()
        .route("/oidc/revoke", post(revocation::revoke))
        .with_state(services.clone())
        .merge(
            Router::new()
                .route("/oidc/introspect", post(management::introspect))
                .with_state(management::ManagementState {
                    management: services.management.clone(),
                }),
        )
        .merge(consumer)
        .layer(DefaultBodyLimit::max(MAX_NATIVE_STATUS_BODY_BYTES));
    let router = router.merge(documents).merge(
        tokens
            .merge(status)
            .layer(middleware::from_fn_with_state(base, client_token_boundary)),
    );
    #[cfg(any(feature = "oidc-web", feature = "saml-web"))]
    let router = services.providers.attach(router, auth, browser)?;
    Ok(router)
}
