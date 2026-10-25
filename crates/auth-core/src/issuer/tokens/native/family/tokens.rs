use super::{ISSUER_NATIVE_ACCESS_LIFETIME_SECONDS, IssuerNativeRefreshData};
use crate::{
    IssuerAuthority, IssuerClientRegistration, IssuerTokenError, IssuerTokenResult, Secret,
};
use std::fmt;

/// Opaque access/refresh credentials are emitted only after successful rotation.
/// Refresh does not mint a new ID token or lengthen the initial ID token's expiry.
pub struct IssuerNativeRotatedTokens {
    access: Secret,
    refresh: Secret,
    expires_in: u32,
    refresh_expires_in: u32,
}
impl IssuerNativeRotatedTokens {
    pub(super) fn committed(
        data: IssuerNativeRefreshData,
        authority: &IssuerAuthority,
        client: &IssuerClientRegistration,
        access: Secret,
        refresh: Secret,
    ) -> IssuerTokenResult<Self> {
        let access_remaining = data
            .access_expires_at_us
            .checked_sub(data.checked_at_us)
            .ok_or(IssuerTokenError::Unavailable)?;
        let refresh_remaining = data
            .refresh_expires_at_us
            .checked_sub(data.checked_at_us)
            .ok_or(IssuerTokenError::Unavailable)?;
        if data.policy.authority() != authority
            || data.policy.client() != client
            || data.family_id.is_nil()
            || data.subject.is_nil()
            || data.generation < 1
            || data.generation > super::MAX_ISSUER_NATIVE_REFRESH_GENERATION
            || data.issued_at_us < 0
            || data.issued_at_us > data.checked_at_us
            || access_remaining < 1_000_000
            || refresh_remaining < 1_000_000
            || data
                .policy
                .grant_expires_at_us(data.prepared_at_us, data.source_absolute_cap_us)
                .map_err(|_| IssuerTokenError::Unavailable)?
                != data.family_expires_at_us
            || data.access_expires_at_us > data.refresh_expires_at_us
            || data.refresh_expires_at_us > data.family_expires_at_us
            || data.access_expires_at_us.saturating_sub(data.issued_at_us)
                > ISSUER_NATIVE_ACCESS_LIFETIME_SECONDS * 1_000_000
            || data.refresh_expires_at_us.saturating_sub(data.issued_at_us)
                > i64::from(data.policy.idle_seconds()) * 1_000_000
        {
            return Err(IssuerTokenError::Unavailable);
        }
        Ok(Self {
            access,
            refresh,
            expires_in: (access_remaining / 1_000_000) as u32,
            refresh_expires_in: (refresh_remaining / 1_000_000) as u32,
        })
    }
    pub fn access_token(&self) -> &Secret {
        &self.access
    }
    pub fn refresh_token(&self) -> &Secret {
        &self.refresh
    }
    pub fn expires_in(&self) -> u32 {
        self.expires_in
    }
    pub fn refresh_expires_in(&self) -> u32 {
        self.refresh_expires_in
    }
}
impl fmt::Debug for IssuerNativeRotatedTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuerNativeRotatedTokens([REDACTED])")
    }
}
