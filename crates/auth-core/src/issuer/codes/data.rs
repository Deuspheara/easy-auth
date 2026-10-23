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
/// Opaque committed code result. Signing/token issuance consumes this value in
/// the later issuer layer; it has no public constructor, Clone or serialization.
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
        if client.realm() != authority.realm()
            || facts.authorization.is_nil()
            || facts.owner.is_nil()
            || facts.session.is_nil()
            || facts.subject.is_nil()
            || !matches!(
                facts.authentication_method.as_str(),
                "email" | "password" | "passkey" | "oidc" | "saml"
            )
            || facts.authenticated_at_us < 0
            || facts.authenticated_at_us > facts.issued_at_us
            || facts.issued_at_us >= facts.expires_at_us
            || facts.expires_at_us > facts.session_expires_at_us
        {
            return Err(IssuerTokenError::Unavailable);
        }
        request::correlation(&facts.nonce).map_err(|_| IssuerTokenError::Unavailable)?;
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
