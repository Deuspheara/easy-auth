//! Closed production activation gate. No environment value is an approval token.
#[cfg(feature = "saml-web")]
mod settings;
#[cfg(feature = "saml-web")]
pub(crate) use settings::Prepared;

use std::{collections::BTreeMap, ffi::OsString};
type StartupResult<T> = Result<T, Box<dyn std::error::Error>>;
const ALLOWED: &[&str] = &[
    "AUTH_SAML_ENABLED",
    "AUTH_SAML_CONNECTION_ID",
    "AUTH_SAML_LOCAL_CLIENT_ID",
    "AUTH_SAML_SP_ENTITY",
    "AUTH_SAML_IDP_ENTITY",
    "AUTH_SAML_SSO_URL",
    "AUTH_SAML_JIT",
];
#[cfg(feature = "saml-web")]
const APPROVAL_REQUIRED: &str =
    "SAML production activation is blocked by the AUTH-32 security approval gates";

pub(crate) enum Configuration {
    Disabled,
    #[cfg(feature = "saml-web")]
    Configured(Box<settings::Settings>),
}
impl Configuration {
    pub fn require_disabled(&self) -> StartupResult<()> {
        match self {
            Self::Disabled => Ok(()),
            #[cfg(feature = "saml-web")]
            Self::Configured(_) => Err(APPROVAL_REQUIRED.into()),
        }
    }
    #[cfg(feature = "saml-web")]
    pub fn prepare(
        self,
        realm: uuid::Uuid,
        browser: &auth_axum::BrowserConfig,
    ) -> StartupResult<Option<Prepared>> {
        match self {
            Self::Disabled => Ok(None),
            Self::Configured(settings) => Ok(Some(settings.prepare(realm, browser)?)),
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
        if !name.to_string_lossy().starts_with("AUTH_SAML_") {
            continue;
        }
        let name = name
            .into_string()
            .map_err(|_| "SAML setting name must be Unicode")?;
        if !ALLOWED.contains(&name.as_str()) {
            return Err("unknown AUTH_SAML setting".into());
        }
        let value = value
            .into_string()
            .map_err(|_| "SAML setting must be Unicode")?;
        if value.len() > 8192 {
            return Err("SAML setting exceeds startup bound".into());
        }
        if values.insert(name, value).is_some() {
            return Err("duplicate SAML setting".into());
        }
    }
    if values.is_empty() {
        return Ok(Configuration::Disabled);
    }
    match values.get("AUTH_SAML_ENABLED").map(String::as_str) {
        Some("false") if values.len() == 1 => return Ok(Configuration::Disabled),
        Some("true") => (),
        _ => {
            return Err("SAML requires AUTH_SAML_ENABLED=true and a complete configuration".into());
        }
    }
    #[cfg(feature = "saml-web")]
    {
        Ok(Configuration::Configured(Box::new(
            settings::Settings::parse(values)?,
        )))
    }
    #[cfg(not(feature = "saml-web"))]
    {
        Err("SAML configuration requires the saml-web server feature; security approval is also required".into())
    }
}

#[cfg(test)]
mod tests;
