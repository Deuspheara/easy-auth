use super::claims::Claims;
use crate::{OAuthConnection, OAuthExchange, OAuthPurpose};
use std::fmt;

/// Verified external identity bound to one consumed transaction. Not a local
/// session or linking grant; final persistence must recheck all original authority.
/// No constructor/Clone/Serialize; nonce, PKCE and raw token are not retained.
#[must_use]
pub struct VerifiedOidcIdentity {
    connection: OAuthConnection,
    purpose: OAuthPurpose,
    expires_us: i64,
    subject: String,
    issued_at: u64,
    authenticated_at: Option<u64>,
    email: Option<String>,
    email_verified: bool,
    #[cfg(feature = "oidc-identities")]
    name: Option<String>,
    #[cfg(feature = "oidc-identities")]
    preferred_username: Option<String>,
}
impl VerifiedOidcIdentity {
    pub(super) fn new(exchange: OAuthExchange, claims: &Claims) -> Self {
        // A verified result cannot extend any authority used to admit it. Token
        // expiry/age remain original caps for the future identity transaction.
        let token_cap = (i128::from(claims.exp) * 1_000_000).min(
            (i128::from(claims.iat) + i128::from(super::claims::MAX_TOKEN_AGE_SECONDS)) * 1_000_000,
        );
        let expires_us = i128::from(exchange.expires_us()).min(token_cap) as i64;
        Self {
            connection: exchange.configuration().clone(),
            purpose: exchange.purpose().clone(),
            expires_us,
            subject: claims.sub.clone(),
            issued_at: claims.iat,
            authenticated_at: claims.auth_time,
            email: claims.email.clone().filter(|value| !value.is_empty()),
            email_verified: claims.email.as_ref().is_some_and(|value| !value.is_empty())
                && claims.email_verified(),
            #[cfg(feature = "oidc-identities")]
            name: claims.name.clone(),
            #[cfg(feature = "oidc-identities")]
            preferred_username: claims.preferred_username.clone(),
        }
    }
    pub fn configuration(&self) -> &OAuthConnection {
        &self.connection
    }
    pub fn purpose(&self) -> &OAuthPurpose {
        &self.purpose
    }
    pub fn expires_us(&self) -> i64 {
        self.expires_us
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }
    /// Provider authentication time, if present. Issuance time is not freshness.
    pub fn authenticated_at(&self) -> Option<u64> {
        self.authenticated_at
    }
    /// Provider attribute only; never local contact or automatic linking authority.
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }
    pub fn email_verified(&self) -> bool {
        self.email_verified
    }
    /// Optional signed presentation metadata; never a stable identity key.
    #[cfg(feature = "oidc-identities")]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    #[cfg(feature = "oidc-identities")]
    pub fn preferred_username(&self) -> Option<&str> {
        self.preferred_username.as_deref()
    }
}
impl fmt::Debug for VerifiedOidcIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedOidcIdentity([REDACTED])")
    }
}
