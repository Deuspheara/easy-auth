#[cfg(feature = "oidc-web")]
mod oidc;

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
    let settings = configuration::oidc::read()?;
    let parameters = configuration::parameters()?;
    #[cfg(feature = "oidc-web")]
    let prepared = match settings {
        configuration::oidc::Configuration::Disabled => None,
        configuration::oidc::Configuration::Enabled(settings) => {
            Some(settings.prepare(parameters.realm, &parameters.browser)?)
        }
    };
    #[cfg(not(feature = "oidc-web"))]
    let _ = settings;
    let (auth, repository) = configuration::load(&parameters).await?;
    #[cfg(feature = "oidc-web")]
    let router = match prepared {
        Some(prepared) => {
            oidc::router(
                auth.clone(),
                parameters.browser.clone(),
                repository,
                prepared,
            )
            .await?
        }
        None => auth_axum::router(auth.clone(), parameters.browser.clone()),
    };
    #[cfg(not(feature = "oidc-web"))]
    let router = {
        drop(repository);
        auth_axum::router(auth.clone(), parameters.browser.clone())
    };
    Ok(ConfiguredApplication {
        auth,
        browser: parameters.browser,
        router,
        bind: parameters.bind,
    })
}
