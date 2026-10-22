use auth_axum::BrowserConfig;
use auth_core::Auth;
use axum::Router;

pub(super) fn router(
    auth: Auth,
    browser: BrowserConfig,
    #[cfg(feature = "oidc-web")] oidc: Option<auth_axum::OidcWebServices>,
    #[cfg(feature = "saml-web")] saml: Option<auth_axum::SamlWebServices>,
) -> auth_core::Result<Router> {
    #[cfg(all(feature = "oidc-web", feature = "saml-web"))]
    let oidc = match (oidc, saml) {
        (Some(oidc), Some(saml)) => {
            return auth_axum::experimental_oidc_saml_web_router(auth, browser, oidc, saml);
        }
        (None, Some(saml)) => return auth_axum::experimental_saml_web_router(auth, browser, saml),
        (oidc, None) => oidc,
    };
    #[cfg(all(feature = "saml-web", not(feature = "oidc-web")))]
    if let Some(saml) = saml {
        return auth_axum::experimental_saml_web_router(auth, browser, saml);
    }
    #[cfg(feature = "oidc-web")]
    if let Some(oidc) = oidc {
        return auth_axum::oidc_web_router(auth, browser, oidc);
    }
    Ok(auth_axum::router(auth, browser))
}
