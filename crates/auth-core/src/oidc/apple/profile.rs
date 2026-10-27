use crate::{Error, Result};
use serde::Deserialize;
use std::fmt;

const MAX_NAME_BYTES: usize = 256;

/// Unsigned first-consent presentation only. Never identity, contact or proof of
/// authentication. Subsequent callbacks may omit it; omission creates no update.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppleInitialProfile {
    #[serde(default)]
    name: Name,
    #[serde(default)]
    email: Option<String>,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Name {
    #[serde(default, rename = "firstName")]
    first: Option<String>,
    #[serde(default, rename = "lastName")]
    last: Option<String>,
}
impl AppleInitialProfile {
    pub(super) fn parse(input: &str) -> Result<Self> {
        let value: Self = serde_json::from_str(input).map_err(|_| Error::Unauthorized)?;
        if [&value.name.first, &value.name.last]
            .into_iter()
            .flatten()
            .any(|s| s.len() > MAX_NAME_BYTES || s.chars().any(char::is_control))
            || value
                .email
                .as_ref()
                .is_some_and(|s| s.len() > 320 || s.chars().any(char::is_control))
        {
            return Err(Error::Unauthorized);
        }
        Ok(value)
    }
    pub fn first_name(&self) -> Option<&str> {
        self.name.first.as_deref()
    }
    pub fn last_name(&self) -> Option<&str> {
        self.name.last.as_deref()
    }
}
impl fmt::Debug for AppleInitialProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppleInitialProfile([REDACTED])")
    }
}
