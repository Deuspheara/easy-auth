#[cfg(feature = "oidc-web")]
#[path = "application/oidc.rs"]
mod oidc;

#[path = "application/routing.rs"]
mod routing;
#[cfg(feature = "saml-web")]
#[path = "application/saml.rs"]
mod saml;

use crate::configuration;
use auth_axum::BrowserConfig;
use auth_core::Auth;
use axum::Router;
use std::net::SocketAddr;

/// Shared validated application for standalone and embedded use. Consumers may
/// merge application routes and own the listener/notification-worker lifetime.
pub struct ConfiguredApplication {
    pub auth: Auth,
    pub browser: BrowserConfig,
    pub router: Router,
    pub bind: SocketAddr,
}

pub async fn configured_application() -> Result<ConfiguredApplication, Box<dyn std::error::Error>> {
    let oidc_settings = configuration::oidc::read()?;
    let parameters = configuration::parameters()?;
    #[cfg(feature = "oidc-web")]
    let oidc_prepared = match oidc_settings {
        configuration::oidc::Configuration::Disabled => None,
        configuration::oidc::Configuration::Enabled(settings) => {
            Some(settings.prepare(parameters.realm, &parameters.browser)?)
        }
    };
    #[cfg(not(feature = "oidc-web"))]
    let _ = oidc_settings;
    let saml_settings = configuration::saml::read()?;
    #[cfg(feature = "saml-web")]
    let saml_prepared = saml_settings.prepare(parameters.realm, &parameters.browser)?;
    #[cfg(not(feature = "saml-web"))]
    saml_settings.require_disabled()?;
    let (auth, repository) = configuration::load(&parameters).await?;
    #[cfg(feature = "oidc-web")]
    let oidc_services = match oidc_prepared {
        Some(prepared) => Some(oidc::services(repository.clone(), prepared).await?),
        None => None,
    };
    #[cfg(feature = "saml-web")]
    let saml_services = match saml_prepared {
        Some(prepared) => Some(saml::services(repository.clone(), prepared).await?),
        None => None,
    };
    drop(repository);
    let router = routing::router(
        auth.clone(),
        parameters.browser.clone(),
        #[cfg(feature = "oidc-web")]
        oidc_services,
        #[cfg(feature = "saml-web")]
        saml_services,
    )?;
    Ok(ConfiguredApplication {
        auth,
        browser: parameters.browser,
        router,
        bind: parameters.bind,
    })
}
