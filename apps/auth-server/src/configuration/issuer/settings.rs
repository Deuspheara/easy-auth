use super::StartupResult;
use auth_axum::BrowserConfig;
use auth_core::{IssuerAuthority, IssuerSigningKey};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};
use uuid::Uuid;

pub(crate) struct Settings {
    key_id: Uuid,
    key_file: PathBuf,
    introspection: bool,
}
pub(crate) struct Prepared {
    pub authority: IssuerAuthority,
    pub key: Arc<IssuerSigningKey>,
    pub introspection: bool,
}
impl Settings {
    pub(super) fn parse(values: BTreeMap<String, String>) -> StartupResult<Self> {
        let key_id: Uuid = values
            .get("AUTH_ISSUER_KEY_ID")
            .ok_or("AUTH_ISSUER_KEY_ID is required")?
            .parse()
            .map_err(|_| "AUTH_ISSUER_KEY_ID must be a nonzero UUID")?;
        if key_id.is_nil() {
            return Err("AUTH_ISSUER_KEY_ID must be a nonzero UUID".into());
        }
        let key_file = values
            .get("AUTH_ISSUER_KEY_FILE")
            .filter(|v| !v.is_empty())
            .ok_or("AUTH_ISSUER_KEY_FILE is required")?;
        let introspection = match values
            .get("AUTH_ISSUER_NATIVE_INTROSPECTION_ENABLED")
            .map(String::as_str)
            .unwrap_or("false")
        {
            "true" => true,
            "false" => false,
            _ => {
                return Err(
                    "AUTH_ISSUER_NATIVE_INTROSPECTION_ENABLED must be true or false".into(),
                );
            }
        };
        Ok(Self {
            key_id,
            key_file: key_file.into(),
            introspection,
        })
    }
    pub(super) fn prepare(self, realm: Uuid, browser: &BrowserConfig) -> StartupResult<Prepared> {
        if !browser.origin().starts_with("https://") {
            return Err("issuer browser composition requires HTTPS".into());
        }
        let authority = IssuerAuthority::new(realm, browser.origin())
            .map_err(|_| "invalid issuer realm or public origin")?;
        let key = crate::load_issuer_signing_key(self.key_id, &self.key_file)
            .map_err(|_| "issuer signing key input is unavailable or invalid")?;
        Ok(Prepared {
            authority,
            key: Arc::new(key),
            introspection: self.introspection,
        })
    }
}
