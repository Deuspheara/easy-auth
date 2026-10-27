use crate::{Error, Result};
use serde::Deserialize;

/// Preserve the signed type until the explicitly selected provider validates it.
/// Generic OIDC/Google continue to reject strings, including "true".
#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum EmailVerification {
    Boolean(bool),
    Text(String),
}
impl EmailVerification {
    pub(super) fn validate(&self, apple: bool) -> Result<()> {
        match self {
            Self::Boolean(_) => Ok(()),
            Self::Text(value) if apple && matches!(value.as_str(), "true" | "false") => Ok(()),
            Self::Text(_) => Err(Error::Unauthorized),
        }
    }
    pub(super) fn verified(&self) -> bool {
        matches!(self, Self::Boolean(true)) || matches!(self, Self::Text(value) if value == "true")
    }
}
