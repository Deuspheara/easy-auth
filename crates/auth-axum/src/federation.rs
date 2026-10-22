//! Shared base routes and one combined contract for explicitly selected providers.
use crate::{Auth, BrowserConfig, OidcWebServices, SamlWebServices, oidc, saml};
use auth_core::Result;
use axum::Router;

/// Engineering composition including gated SAML. This is not security approval.
/// Both sources must match the supplied realm and exact HTTPS callbacks.
pub fn experimental_oidc_saml_web_router(
    auth: Auth,
    browser: BrowserConfig,
    oidc_services: OidcWebServices,
    saml_services: SamlWebServices,
) -> Result<Router> {
    let mut api = crate::oidc_web_openapi();
    api.merge(saml::web_contract(&saml_services));
    let router = crate::router::configured_router(auth.clone(), browser.clone(), api);
    let router = oidc::attach(router, auth.clone(), browser.clone(), oidc_services)?;
    saml::attach(router, auth, browser, saml_services)
}
