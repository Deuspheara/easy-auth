use super::super::payload::{GrantTokenKind, StoredGrant};
use crate::{AppleClientSecret, Result};
use std::fmt;
use zeroize::Zeroizing;
pub struct AppleRevocationRequest {
    form: Zeroizing<String>,
}
impl AppleRevocationRequest {
    pub(super) fn new(client: &str, secret: AppleClientSecret, grant: StoredGrant) -> Result<Self> {
        grant.validate()?;
        let hint = match grant.kind {
            GrantTokenKind::Refresh => "refresh_token",
            GrantTokenKind::Access => "access_token",
        };
        Ok(Self {
            form: secret.revocation_form(client, &grant.token, hint)?,
        })
    }
    /// Protected transport only. Never log, render, persist or put this in a URL.
    pub fn form(&self) -> &str {
        &self.form
    }
}
impl fmt::Debug for AppleRevocationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppleRevocationRequest([REDACTED])")
    }
}
