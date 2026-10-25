use crate::{
    Error, ISSUER_AUTHORIZATION_LIFETIME_SECONDS, ISSUER_CODE_LIFETIME_SECONDS, IssuerAuthority,
    IssuerAuthorizationDestination, IssuerAuthorizationStart, IssuerClientRegistration,
    IssuerNativeRefreshPolicy, Result, Secret,
};
use uuid::Uuid;

/// Trusted persistence facts, not a proof. Proposed bounds never slide at approval.
pub struct IssuerNativeConsentData {
    pub policy: IssuerNativeRefreshPolicy,
    pub prepared_at_us: i64,
    pub source_absolute_cap_us: i64,
    pub grant_expires_at_us: i64,
    pub approved_at_us: Option<i64>,
}
impl IssuerNativeConsentData {
    pub(in crate::issuer) fn validate(
        &self,
        authority: &IssuerAuthority,
        client: &IssuerClientRegistration,
        expires: i64,
        approved: bool,
    ) -> Result<()> {
        let proposed_cap = self
            .prepared_at_us
            .checked_add(ISSUER_AUTHORIZATION_LIFETIME_SECONDS * 1_000_000)
            .ok_or(Error::Unavailable)?;
        if self.policy.authority() != authority
            || self.policy.client() != client
            || self
                .policy
                .grant_expires_at_us(self.prepared_at_us, self.source_absolute_cap_us)
                .map_err(|_| Error::Unavailable)?
                != self.grant_expires_at_us
            || expires <= self.prepared_at_us
            || expires > proposed_cap
            || expires > self.grant_expires_at_us
        {
            return Err(Error::Unavailable);
        }
        match (approved, self.approved_at_us) {
            (false, None) => Ok(()),
            (true, Some(at))
                if at >= self.prepared_at_us
                    && at < expires
                    && expires
                        <= at
                            .checked_add(ISSUER_CODE_LIFETIME_SECONDS * 1_000_000)
                            .ok_or(Error::Unavailable)? =>
            {
                Ok(())
            }
            _ => Err(Error::Unavailable),
        }
    }
}
pub struct IssuerNativeAuthorizationPreparation {
    pub expires_at_us: i64,
    pub consent: IssuerNativeConsentData,
}
pub struct IssuerNativeAuthorizationDestination {
    pub destination: IssuerAuthorizationDestination,
    pub consent: IssuerNativeConsentData,
}
/// Safe display metadata, not approval or client/owner authority.
pub struct IssuerNativeAuthorizationPreview {
    pub authorization: Uuid,
    pub client: Uuid,
    pub redirect_uri: String,
    pub expires_at_us: i64,
    pub grant_expires_at_us: i64,
    pub idle_seconds: u32,
}
pub struct IssuerNativeAuthorizationStart {
    pub(super) code: IssuerAuthorizationStart,
    pub(super) grant_expires_at_us: i64,
    pub(super) idle_seconds: u32,
}
impl IssuerNativeAuthorizationStart {
    pub fn authorization(&self) -> Uuid {
        self.code.authorization()
    }
    pub fn handle(&self) -> &Secret {
        self.code.handle()
    }
    pub fn client(&self) -> Uuid {
        self.code.client()
    }
    pub fn redirect_uri(&self) -> &str {
        self.code.redirect_uri()
    }
    pub fn expires_at_us(&self) -> i64 {
        self.code.expires_at_us()
    }
    pub fn grant_expires_at_us(&self) -> i64 {
        self.grant_expires_at_us
    }
    pub fn idle_seconds(&self) -> u32 {
        self.idle_seconds
    }
}
