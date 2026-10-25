//! Explicit inbound-provider attachment around the same outbound issuer routes.
use super::IssuerNativeWebServices;
use crate::{Auth, BrowserConfig};
use auth_core::Result;
use axum::Router;

#[derive(Clone, Default)]
pub(super) struct Providers {
    #[cfg(feature = "oidc-web")]
    oidc: Option<crate::OidcWebServices>,
    #[cfg(feature = "saml-web")]
    saml: Option<crate::SamlWebServices>,
}
impl IssuerNativeWebServices {
    #[cfg(feature = "oidc-web")]
    pub fn with_oidc_provider(mut self, provider: crate::OidcWebServices) -> Self {
        self.providers.oidc = Some(provider);
        self
    }
    #[cfg(feature = "saml-web")]
    pub fn with_saml_provider(mut self, provider: crate::SamlWebServices) -> Self {
        self.providers.saml = Some(provider);
        self
    }
}
impl Providers {
    pub(super) fn contract(&self, mut api: utoipa::openapi::OpenApi) -> utoipa::openapi::OpenApi {
        #[cfg(feature = "oidc-web")]
        if self.oidc.is_some() {
            api.merge(crate::oidc_web_openapi());
        }
        #[cfg(feature = "saml-web")]
        if let Some(saml) = &self.saml {
            api.merge(crate::saml::web_contract(saml));
        }
        api
    }
    pub(super) fn attach(
        &self,
        mut router: Router,
        auth: Auth,
        browser: BrowserConfig,
    ) -> Result<Router> {
        #[cfg(feature = "oidc-web")]
        if let Some(oidc) = &self.oidc {
            router = crate::oidc::attach(router, auth.clone(), browser.clone(), oidc.clone())?;
        }
        #[cfg(feature = "saml-web")]
        if let Some(saml) = &self.saml {
            router = crate::saml::attach(router, auth.clone(), browser.clone(), saml.clone())?;
        }
        // Wrap all selected routes so session removal through any method clears
        // retained OIDC proofs too. Each provider retains its own realm checks.
        #[cfg(feature = "oidc-web")]
        if self.oidc.is_some() {
            router = crate::oidc::clear_proofs(router, browser);
        }
        Ok(router)
    }
}
