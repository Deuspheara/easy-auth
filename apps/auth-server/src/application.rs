use crate::configured_auth;
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
    let (auth, browser, bind) = configured_auth().await?;
    let router = auth_axum::router(auth.clone(), browser.clone());
    Ok(ConfiguredApplication {
        auth,
        browser,
        router,
        bind,
    })
}
