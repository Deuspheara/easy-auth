#[cfg(feature = "oidc-web")]
mod secret_file;
#[cfg(feature = "oidc-web")]
mod settings;
#[cfg(feature = "oidc-web")]
pub(crate) use settings::{Prepared, Settings};

use std::{collections::BTreeMap, ffi::OsString};

type StartupResult<T> = Result<T, Box<dyn std::error::Error>>;
const PREFIX: &str = "AUTH_OIDC_";
const ALLOWED: &[&str] = &[
    "AUTH_OIDC_ENABLED",
    "AUTH_OIDC_CONNECTION_ID",
    "AUTH_OIDC_LOCAL_CLIENT_ID",
    "AUTH_OIDC_ISSUER",
    "AUTH_OIDC_PROVIDER_CLIENT_ID",
    "AUTH_OIDC_ALLOWED_ORIGINS",
    "AUTH_OIDC_CLIENT_AUTH_METHOD",
    "AUTH_OIDC_CLIENT_SECRET_FILE",
    "AUTH_OIDC_DISPLAY_CLAIM",
    "AUTH_OIDC_JIT",
    "AUTH_OIDC_SIGNING_ALGORITHMS",
    "AUTH_OIDC_MIXUP_DEFENSE",
];

pub(crate) enum Configuration {
    Disabled,
    #[cfg(feature = "oidc-web")]
    Enabled(Box<Settings>),
}
impl Configuration {
    pub fn enabled(&self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

pub(crate) fn read() -> StartupResult<Configuration> {
    parse(std::env::vars_os())
}
fn parse(
    environment: impl IntoIterator<Item = (OsString, OsString)>,
) -> StartupResult<Configuration> {
    let mut values = BTreeMap::new();
    for (name, value) in environment {
        if !name.to_string_lossy().starts_with(PREFIX) {
            continue;
        }
        let name = name
            .into_string()
            .map_err(|_| "OIDC setting name must be Unicode")?;
        if !ALLOWED.contains(&name.as_str()) {
            return Err("unknown AUTH_OIDC setting".into());
        }
        let value = value
            .into_string()
            .map_err(|_| "OIDC setting must be Unicode")?;
        if value.len() > 8192 {
            return Err("OIDC setting exceeds startup bound".into());
        }
        if values.insert(name, value).is_some() {
            return Err("duplicate OIDC setting".into());
        }
    }
    if values.is_empty() {
        return Ok(Configuration::Disabled);
    }
    match values.get("AUTH_OIDC_ENABLED").map(String::as_str) {
        Some("false") if values.len() == 1 => return Ok(Configuration::Disabled),
        Some("true") => (),
        _ => {
            return Err("OIDC requires AUTH_OIDC_ENABLED=true and a complete configuration".into());
        }
    }
    #[cfg(feature = "oidc-web")]
    {
        Ok(Configuration::Enabled(Box::new(Settings::parse(values)?)))
    }
    #[cfg(not(feature = "oidc-web"))]
    {
        Err("OIDC configuration requires the oidc-web server feature".into())
    }
}

#[cfg(test)]
mod tests;
