use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const MAX_GRANT_TOKEN_BYTES: usize = 16 * 1024;
pub(super) const MAX_PAYLOAD_BYTES: usize = 40 * 1024;
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum GrantTokenKind {
    Refresh,
    Access,
}

// Construct only after the same initiated code exchange's signed proof passed.
// This type has no public credential accessor or constructor.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredGrant {
    pub version: u8,
    pub kind: GrantTokenKind,
    pub token: String,
    pub provider_client: String,
    pub access_expires_us: Option<i64>,
}
impl StoredGrant {
    pub fn validate(&self) -> Result<()> {
        let expiry_valid = match self.kind {
            GrantTokenKind::Refresh => self.access_expires_us.is_none(),
            GrantTokenKind::Access => self.access_expires_us.is_some_and(|v| v > 0),
        };
        if self.provider_client.is_empty()
            || self.provider_client.len() > 1024
            || !self
                .provider_client
                .bytes()
                .all(|b| (0x20..=0x7e).contains(&b))
            || self.version != 1
            || self.token.is_empty()
            || self.token.len() > MAX_GRANT_TOKEN_BYTES
            || !self.token.bytes().all(|b| (0x20..=0x7e).contains(&b))
            || !expiry_valid
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}
impl Drop for StoredGrant {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}
