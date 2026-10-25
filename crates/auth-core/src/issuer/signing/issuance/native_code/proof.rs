use super::{IssuerNativeTokenCommit, IssuerNativeTokenPreparationData};
use crate::{
    IssuerCodeRedemption, IssuerGrantData, IssuerNativeConsentData, IssuerSigningSnapshot,
    IssuerTokenError, IssuerTokenResult, Secret, Verifier,
};
use std::fmt;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub(super) struct NativeStaged {
    pub data: IssuerNativeTokenPreparationData,
}
impl Drop for NativeStaged {
    fn drop(&mut self) {
        self.data.token.grant.nonce.zeroize();
        self.data.token.code_snapshot.zeroize();
        self.data.consent_snapshot.zeroize();
    }
}
/// Produced only by concrete RS256 signing, not a public proof constructor.
pub struct IssuerNativeSignedCode<'a> {
    pub(super) request: IssuerCodeRedemption<'a>,
    pub(super) staged: NativeStaged,
    pub(super) family: Uuid,
    pub(super) access_id: Uuid,
    pub(super) access: Secret,
    pub(super) refresh: Secret,
    pub(super) id_token: Zeroizing<String>,
    pub(super) expires: i64,
}
impl IssuerNativeSignedCode<'_> {
    pub fn redemption(&self) -> &IssuerCodeRedemption<'_> {
        &self.request
    }
    pub fn grant(&self) -> &IssuerGrantData {
        &self.staged.data.token.grant
    }
    pub fn signing(&self) -> &IssuerSigningSnapshot {
        &self.staged.data.token.signing
    }
    pub fn consent(&self) -> &IssuerNativeConsentData {
        &self.staged.data.consent
    }
    pub fn code_snapshot(&self) -> &str {
        &self.staged.data.token.code_snapshot
    }
    pub fn consent_snapshot(&self) -> &str {
        &self.staged.data.consent_snapshot
    }
    pub fn family_id(&self) -> Uuid {
        self.family
    }
    pub fn access_id(&self) -> Uuid {
        self.access_id
    }
    pub fn access_verifier(&self) -> Verifier {
        self.access.verifier()
    }
    pub fn refresh_verifier(&self) -> Verifier {
        self.refresh.verifier()
    }
    pub fn expires_at_us(&self) -> i64 {
        self.expires
    }
    pub(super) fn finish(
        self,
        commit: IssuerNativeTokenCommit,
    ) -> IssuerTokenResult<IssuerNativeTokens> {
        let access_remaining = self
            .expires
            .checked_sub(commit.committed_at_us)
            .ok_or(IssuerTokenError::Unavailable)?;
        let refresh_remaining = commit
            .refresh_expires_at_us
            .checked_sub(commit.committed_at_us)
            .ok_or(IssuerTokenError::Unavailable)?;
        if commit.committed_at_us < self.grant().issued_at_us
            || access_remaining < 1_000_000
            || refresh_remaining < 1_000_000
            || commit.refresh_expires_at_us > self.consent().grant_expires_at_us
            || refresh_remaining > i64::from(self.consent().policy.idle_seconds()) * 1_000_000
        {
            return Err(IssuerTokenError::Unavailable);
        }
        Ok(IssuerNativeTokens {
            access: self.access,
            refresh: self.refresh,
            id_token: self.id_token,
            expires_in: (access_remaining / 1_000_000) as u32,
            refresh_expires_in: (refresh_remaining / 1_000_000) as u32,
        })
    }
}
impl fmt::Debug for IssuerNativeSignedCode<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuerNativeSignedCode([REDACTED])")
    }
}
/// Wire credentials exist only after the complete native family/code commit.
pub struct IssuerNativeTokens {
    access: Secret,
    refresh: Secret,
    id_token: Zeroizing<String>,
    expires_in: u32,
    refresh_expires_in: u32,
}
impl IssuerNativeTokens {
    pub fn access_token(&self) -> &Secret {
        &self.access
    }
    pub fn refresh_token(&self) -> &Secret {
        &self.refresh
    }
    pub fn id_token(&self) -> &str {
        &self.id_token
    }
    pub fn expires_in(&self) -> u32 {
        self.expires_in
    }
    pub fn refresh_expires_in(&self) -> u32 {
        self.refresh_expires_in
    }
}
impl fmt::Debug for IssuerNativeTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuerNativeTokens([REDACTED])")
    }
}
