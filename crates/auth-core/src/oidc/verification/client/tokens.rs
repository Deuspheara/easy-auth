use super::{OidcClientError, OidcClientResult};
use crate::OidcIdToken;
use std::fmt;
use zeroize::Zeroizing;

/// Opaque client credential. Restore/expose only through protected transport or
/// per-user storage; it is never a local session/identity proof.
pub struct OidcClientCredential(Zeroizing<String>);
impl OidcClientCredential {
    pub fn parse(value: String) -> OidcClientResult<Self> {
        let value = Zeroizing::new(value);
        if value.is_empty()
            || value.len() > 1024
            || value.bytes().any(|b| !(0x21..=0x7e).contains(&b))
        {
            return Err(OidcClientError::Protocol);
        }
        Ok(Self(value))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for OidcClientCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcClientCredential([REDACTED])")
    }
}
/// Verified RP metadata only. No conversion to a provider identity or local
/// session is supplied; the application owns its own session/authorization policy.
pub struct OidcClientIdentity {
    pub(super) issuer: String,
    pub(super) client: uuid::Uuid,
    pub(super) subject: String,
    pub(super) issued_at: u64,
    pub(super) authenticated_at: Option<u64>,
    pub(super) expires_us: i64,
}
impl OidcClientIdentity {
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn client(&self) -> uuid::Uuid {
        self.client
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }
    pub fn authenticated_at(&self) -> Option<u64> {
        self.authenticated_at
    }
    pub fn expires_us(&self) -> i64 {
        self.expires_us
    }
}
impl fmt::Debug for OidcClientIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcClientIdentity([REDACTED])")
    }
}
pub struct OidcClientTokens {
    pub(super) identity: OidcClientIdentity,
    pub(super) credentials: OidcClientCredentials,
}
impl OidcClientTokens {
    pub fn identity(&self) -> &OidcClientIdentity {
        &self.identity
    }
    pub fn access_token(&self) -> &OidcClientCredential {
        &self.credentials.access
    }
    pub fn access_expires_us(&self) -> i64 {
        self.credentials.access_expires_us
    }
    pub fn refresh_token(&self) -> Option<&OidcClientCredential> {
        self.credentials.refresh.as_ref()
    }
    pub fn refresh_expires_us(&self) -> Option<i64> {
        self.credentials.refresh_expires_us
    }
    /// Move the current generation into a single-use refresh operation or vault.
    pub fn take_refresh_token(&mut self) -> Option<OidcClientCredential> {
        self.credentials.refresh.take()
    }
}
pub struct OidcClientCredentials {
    pub(super) access: OidcClientCredential,
    pub(super) refresh: Option<OidcClientCredential>,
    pub(super) access_expires_us: i64,
    pub(super) refresh_expires_us: Option<i64>,
}
impl OidcClientCredentials {
    pub fn access_token(&self) -> &OidcClientCredential {
        &self.access
    }
    pub fn access_expires_us(&self) -> i64 {
        self.access_expires_us
    }
    pub fn refresh_token(&self) -> Option<&OidcClientCredential> {
        self.refresh.as_ref()
    }
    pub fn refresh_expires_us(&self) -> Option<i64> {
        self.refresh_expires_us
    }
    pub fn take_refresh_token(&mut self) -> Option<OidcClientCredential> {
        self.refresh.take()
    }
}
impl fmt::Debug for OidcClientCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcClientCredentials([REDACTED])")
    }
}
pub(super) struct InitialTokens {
    pub(super) id: OidcIdToken,
    pub(super) credentials: OidcClientCredentials,
}
