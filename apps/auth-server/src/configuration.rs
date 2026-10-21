#[path = "configuration/database.rs"]
mod database;
#[path = "configuration/environment.rs"]
mod environment;
#[path = "configuration/mail.rs"]
mod mail;
#[path = "configuration/oidc/mod.rs"]
pub(crate) mod oidc;
#[path = "configuration/passwords.rs"]
mod passwords;

use auth_axum::BrowserConfig;
use auth_core::Auth;
use auth_postgres::Postgres;
use environment::{optional_setting, required_setting, setting};
use std::{net::SocketAddr, sync::Arc};
use uuid::Uuid;

type StartupResult<T> = Result<T, Box<dyn std::error::Error>>;

pub(crate) struct Parameters {
    pub browser: BrowserConfig,
    pub bind: SocketAddr,
    pub realm: Uuid,
    development: bool,
}

/// Auth-only compatibility API. Explicit OIDC browser settings require the shared
/// application factory so they cannot be silently dropped by an older consumer.
pub async fn configured_auth() -> StartupResult<(Auth, BrowserConfig, SocketAddr)> {
    if oidc::read()?.enabled() {
        return Err("OIDC browser settings require configured_application".into());
    }
    let parameters = parameters()?;
    let (auth, _) = load(&parameters).await?;
    Ok((auth, parameters.browser, parameters.bind))
}

pub(crate) fn parameters() -> StartupResult<Parameters> {
    let development = match setting("AUTH_DEVELOPMENT", "false")?.as_str() {
        "true" => true,
        "false" => false,
        _ => return Err("AUTH_DEVELOPMENT must be true or false".into()),
    };
    let browser = BrowserConfig::new(
        &setting("AUTH_PUBLIC_URL", "http://127.0.0.1:8080")?,
        development,
    )
    .map_err(
        |_| "AUTH_PUBLIC_URL must be an allowed origin (HTTPS, or loopback HTTP in development)",
    )?;
    let bind: SocketAddr = setting("AUTH_BIND", "127.0.0.1:8080")?
        .parse()
        .map_err(|_| "AUTH_BIND must be a socket address")?;
    if development && !bind.ip().is_loopback() {
        return Err("development bind must be loopback".into());
    }
    let realm: Uuid = required_setting("AUTH_REALM_ID")?
        .parse()
        .map_err(|_| "AUTH_REALM_ID must be a UUID")?;
    Ok(Parameters {
        browser,
        bind,
        realm,
        development,
    })
}

pub(crate) async fn load(parameters: &Parameters) -> StartupResult<(Auth, Arc<Postgres>)> {
    let mailer = mail::delivery(&parameters.browser, parameters.development)?;
    let repository = database::repository(parameters.realm).await?;
    let auth = Auth::new(parameters.realm, repository.clone(), Arc::new(mailer));
    let auth = passwords::attach(auth, parameters.development)?;
    if parameters.development {
        tracing::warn!("development_http_and_smtp_enabled");
    }
    Ok((auth, repository))
}
