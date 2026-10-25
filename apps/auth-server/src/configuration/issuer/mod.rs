//! Fail-closed opt-in; startup never provisions a registration, policy or key.
#[cfg(feature = "issuer-web")]
mod settings;
#[cfg(feature = "issuer-web")]
pub(crate) use settings::Prepared;
use std::{collections::BTreeMap, ffi::OsString};
type StartupResult<T> = Result<T, Box<dyn std::error::Error>>;
const ALLOWED: &[&str] = &[
    "AUTH_ISSUER_ENABLED",
    "AUTH_ISSUER_KEY_ID",
    "AUTH_ISSUER_KEY_FILE",
    "AUTH_ISSUER_NATIVE_INTROSPECTION_ENABLED",
];
pub(crate) enum Configuration {
    Disabled,
    #[cfg(feature = "issuer-web")]
    Enabled(settings::Settings),
}
impl Configuration {
    pub fn enabled(&self) -> bool {
        !matches!(self, Self::Disabled)
    }
    #[cfg(feature = "issuer-web")]
    pub fn prepare(
        self,
        realm: uuid::Uuid,
        browser: &auth_axum::BrowserConfig,
    ) -> StartupResult<Option<Prepared>> {
        match self {
            Self::Disabled => Ok(None),
            Self::Enabled(settings) => Ok(Some(settings.prepare(realm, browser)?)),
        }
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
        if !name.to_string_lossy().starts_with("AUTH_ISSUER_") {
            continue;
        }
        let name = name
            .into_string()
            .map_err(|_| "issuer setting name must be Unicode")?;
        if !ALLOWED.contains(&name.as_str()) {
            return Err("unknown AUTH_ISSUER setting".into());
        }
        let value = value
            .into_string()
            .map_err(|_| "issuer setting must be Unicode")?;
        if value.len() > 8192 {
            return Err("issuer setting exceeds startup bound".into());
        }
        if values.insert(name, value).is_some() {
            return Err("duplicate issuer setting".into());
        }
    }
    if values.is_empty() {
        return Ok(Configuration::Disabled);
    }
    match values.get("AUTH_ISSUER_ENABLED").map(String::as_str) {
        Some("false") if values.len() == 1 => return Ok(Configuration::Disabled),
        Some("true") => (),
        _ => {
            return Err(
                "issuer requires AUTH_ISSUER_ENABLED=true and a complete configuration".into(),
            );
        }
    }
    #[cfg(feature = "issuer-web")]
    {
        Ok(Configuration::Enabled(settings::Settings::parse(values)?))
    }
    #[cfg(not(feature = "issuer-web"))]
    {
        Err("issuer configuration requires the issuer-web server feature".into())
    }
}
#[cfg(test)]
mod tests;
