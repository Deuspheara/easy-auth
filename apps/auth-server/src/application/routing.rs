use auth_axum::BrowserConfig;
use auth_core::Auth;
use axum::Router;

pub(super) fn router(
    auth: Auth,
    browser: BrowserConfig,
    #[cfg(feature = "issuer-web")] issuer: Option<auth_axum::IssuerNativeWebServices>,
    #[cfg(feature = "oidc-web")] oidc: Option<auth_axum::OidcWebServices>,
    #[cfg(feature = "saml-web")] saml: Option<auth_axum::SamlWebServices>,
) -> auth_core::Result<Router> {
    #[cfg(feature = "issuer-web")]
    if let Some(issuer) = issuer {
        #[cfg(feature = "oidc-web")]
        let issuer = match oidc {
            Some(provider) => issuer.with_oidc_provider(provider),
            None => issuer,
        };
        #[cfg(feature = "saml-web")]
        let issuer = match saml {
            Some(provider) => issuer.with_saml_provider(provider),
            None => issuer,
        };
        return auth_axum::experimental_issuer_native_web_router(auth, browser, issuer);
    }
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
