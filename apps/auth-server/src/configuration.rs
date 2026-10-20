mod database;
mod mail;
mod passwords;

use auth_axum::BrowserConfig;
use auth_core::Auth;
use std::{env, net::SocketAddr, sync::Arc};
use uuid::Uuid;

fn setting(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_owned())
}

/// Compose database, email and shared auth for the binary or embedded example.
/// Values are validated before returning; no configuration secrets are logged.
pub async fn configured_auth()
-> Result<(Auth, BrowserConfig, SocketAddr), Box<dyn std::error::Error>> {
    let development = match setting("AUTH_DEVELOPMENT", "false").as_str() {
        "true" => true,
        "false" => false,
        _ => return Err("AUTH_DEVELOPMENT must be true or false".into()),
    };
    let browser = BrowserConfig::new(
        &setting("AUTH_PUBLIC_URL", "http://127.0.0.1:8080"),
        development,
    )?;
    let bind: SocketAddr = setting("AUTH_BIND", "127.0.0.1:8080").parse()?;
    if development && !bind.ip().is_loopback() {
        return Err("development bind must be loopback".into());
    }
    let realm: Uuid = env::var("AUTH_REALM_ID")
        .map_err(|_| "AUTH_REALM_ID is required")?
        .parse()?;
    let mailer = mail::delivery(&browser, development)?;
    let repository = database::repository(realm).await?;
    let auth = Auth::new(realm, repository, Arc::new(mailer));
    let auth = passwords::attach(auth, development)?;
    if development {
        tracing::warn!("development_http_and_smtp_enabled");
    }
    Ok((auth, browser, bind))
}
