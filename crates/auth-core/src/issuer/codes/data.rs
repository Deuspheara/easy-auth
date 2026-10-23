use super::{IssuerAuthority, IssuerTokenError, IssuerTokenResult, request};
use crate::{IssuerClientRegistration, Secret};
use std::fmt;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

/// Public consent metadata only; private credentials and correlation stay hidden.
pub struct IssuerAuthorizationPreview {
    pub authorization: Uuid,
    pub client: Uuid,
    pub redirect_uri: String,
    pub expires_at_us: i64,
}
pub struct IssuerAuthorizationStart {
    pub(super) authorization: Uuid,
    pub(super) handle: Secret,
    pub(super) client: Uuid,
    pub(super) redirect: String,
    pub(super) expires: i64,
}
impl IssuerAuthorizationStart {
    pub(in crate::issuer) fn from_saved(
        request: &super::IssuerAuthorizationRequest,
        handle: Secret,
        expires: i64,
    ) -> Self {
        Self {
            authorization: request.id(),
            handle,
            client: request.client().client(),
            redirect: request.redirect_uri().to_owned(),
            expires,
        }
    }
    /// Public selector for the preview being confirmed, not an authorization
    /// credential. Both private cookies and the initiating session remain needed.
    pub fn authorization(&self) -> Uuid {
        self.authorization
    }
    pub fn handle(&self) -> &Secret {
        &self.handle
    }
    pub fn client(&self) -> Uuid {
        self.client
    }
    pub fn redirect_uri(&self) -> &str {
        &self.redirect
    }
    pub fn expires_at_us(&self) -> i64 {
        self.expires
    }
}
/// Trusted repository output, not a consent or authorization proof. Core still
/// validates the destination before emitting any response URL.
pub struct IssuerAuthorizationDestination {
    pub client: IssuerClientRegistration,
    pub redirect_uri: String,
    pub state: String,
    pub expires_at_us: i64,
}
pub struct IssuerAuthorizationReturn(pub(super) Zeroizing<String>);
impl IssuerAuthorizationReturn {
    pub fn url(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for IssuerAuthorizationReturn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuerAuthorizationReturn([REDACTED])")
    }
}

/// Facts returned only by the trusted repository after committed one-use code
/// redemption. This DTO alone is not a protocol proof or token.
pub struct IssuerGrantData {
    pub authorization: Uuid,
    pub owner: Uuid,
    pub session: Uuid,
    pub subject: Uuid,
    pub nonce: String,
    pub authentication_method: String,
    pub authenticated_at_us: i64,
    pub issued_at_us: i64,
    pub expires_at_us: i64,
    pub session_expires_at_us: i64,
}
impl IssuerGrantData {
    pub(in crate::issuer) fn validate(
        &self,
        authority: &IssuerAuthority,
        client: &IssuerClientRegistration,
    ) -> IssuerTokenResult<()> {
        if !client.supports_online_authorization() {
            return Err(IssuerTokenError::Unavailable);
        }
        self.validate_common(authority, client)
    }
    /// Shared identity/time facts only. Explicit callers must independently
    /// enforce their online/native profile and original authorization policy.
    pub(in crate::issuer) fn validate_common(
        &self,
        authority: &IssuerAuthority,
        client: &IssuerClientRegistration,
    ) -> IssuerTokenResult<()> {
        if client.realm() != authority.realm()
            || self.authorization.is_nil()
            || self.owner.is_nil()
            || self.session.is_nil()
            || self.subject.is_nil()
            || !matches!(
                self.authentication_method.as_str(),
                "email" | "password" | "passkey" | "oidc" | "saml"
            )
            || self.authenticated_at_us < 0
            || self.authenticated_at_us > self.issued_at_us
            || self.issued_at_us >= self.expires_at_us
            || self.expires_at_us > self.session_expires_at_us
        {
            return Err(IssuerTokenError::Unavailable);
        }
        request::correlation(&self.nonce).map_err(|_| IssuerTokenError::Unavailable)?;
        Ok(())
    }
}
/// Opaque committed code-component result, not signing authority. Signed token
/// issuance uses its separate staged/final-check flow. This value has no public
/// constructor, Clone or serialization.
pub struct IssuerRedeemedCode {
    pub(super) authority: IssuerAuthority,
    pub(super) client: IssuerClientRegistration,
    pub(super) facts: IssuerGrantData,
}
impl IssuerRedeemedCode {
    pub(super) fn from_repository(
        authority: IssuerAuthority,
        client: IssuerClientRegistration,
        facts: IssuerGrantData,
    ) -> IssuerTokenResult<Self> {
        facts.validate(&authority, &client)?;
        Ok(Self {
            authority,
            client,
            facts,
        })
    }
    pub fn authority(&self) -> &IssuerAuthority {
        &self.authority
    }
    pub fn client(&self) -> &IssuerClientRegistration {
        &self.client
    }
    pub fn authorization(&self) -> Uuid {
        self.facts.authorization
    }
    /// Internal local owner identifier; never serialize as an OIDC subject.
    pub fn owner(&self) -> Uuid {
        self.facts.owner
    }
    pub fn session(&self) -> Uuid {
        self.facts.session
    }
    pub fn subject(&self) -> Uuid {
        self.facts.subject
    }
    pub fn nonce(&self) -> &str {
        &self.facts.nonce
    }
    /// Actual initiating method; this is not a certified MFA/AAL assertion.
    pub fn authentication_method(&self) -> &str {
        &self.facts.authentication_method
    }
    pub fn authenticated_at_us(&self) -> i64 {
        self.facts.authenticated_at_us
    }
    pub fn issued_at_us(&self) -> i64 {
        self.facts.issued_at_us
    }
    pub fn expires_at_us(&self) -> i64 {
        self.facts.expires_at_us
    }
    pub fn session_expires_at_us(&self) -> i64 {
        self.facts.session_expires_at_us
    }
}
impl fmt::Debug for IssuerRedeemedCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuerRedeemedCode([REDACTED])")
    }
}
impl Drop for IssuerRedeemedCode {
    fn drop(&mut self) {
        self.facts.nonce.zeroize();
    }
}
