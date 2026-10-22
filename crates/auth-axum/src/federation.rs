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
    let router = saml::attach(router, auth, browser.clone(), saml_services)?;
    // Wrap every selected route, including SAML deletion responses that clear
    // the session. Layering before attaching SAML misses those responses.
    Ok(oidc::clear_proofs(router, browser))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
        routing::post,
    };
    use tower::ServiceExt;

    /// Transport-only response convention; this handler creates no local identity,
    /// verified assertion or erasure. Real deletion is covered by the PG/HTTP suites.
    #[tokio::test]
    async fn outer_cleanup_clears_oidc_proofs_on_other_provider_session_removal() {
        let browser = BrowserConfig::new("https://app.example", false).unwrap();
        let cookie = browser.cookie(browser.session_name(), None, 0);
        let selected_routes = Router::new().route(
            "/saml/account-delete-response",
            post(move || async move { (StatusCode::NO_CONTENT, [(header::SET_COOKIE, cookie)]) }),
        );
        let app = oidc::clear_proofs(selected_routes, browser);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/saml/account-delete-response")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let cookies: Vec<_> = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        for name in [
            "__Host-auth-oidc-signin-browser",
            "__Host-auth-oidc-delete-browser",
        ] {
            assert!(
                cookies
                    .iter()
                    .any(|value| value.starts_with(name) && value.contains("Max-Age=0"))
            );
        }
    }
}
