use super::IssuerTokenPreparationData;
use crate::{IssuerCodeRedemption, IssuerGrantData, IssuerSigningSnapshot, Secret, Verifier};
use std::fmt;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub(super) struct StagedData {
    pub data: IssuerTokenPreparationData,
}
impl Drop for StagedData {
    fn drop(&mut self) {
        self.data.grant.nonce.zeroize();
        self.data.code_snapshot.zeroize();
    }
}
/// Produced only after concrete RS256 signing. It contains no public constructor,
/// Clone, serialization or raw-ID-token projection for a persistence adapter.
pub struct IssuerSignedCode<'a> {
    pub(super) request: IssuerCodeRedemption<'a>,
    pub(super) staged: StagedData,
    pub(super) token_id: Uuid,
    pub(super) access: Secret,
    pub(super) id_token: Zeroizing<String>,
    pub(super) expires_at_us: i64,
}
impl IssuerSignedCode<'_> {
    pub fn redemption(&self) -> &IssuerCodeRedemption<'_> {
        &self.request
    }
    pub fn signing(&self) -> &IssuerSigningSnapshot {
        &self.staged.data.signing
    }
    pub fn grant(&self) -> &IssuerGrantData {
        &self.staged.data.grant
    }
    /// Exact PostgreSQL JSONB snapshot; repository-only, never a wire response.
    pub fn code_snapshot(&self) -> &str {
        &self.staged.data.code_snapshot
    }
    pub fn token_id(&self) -> Uuid {
        self.token_id
    }
    pub fn access_verifier(&self) -> Verifier {
        self.access.verifier()
    }
    pub fn expires_at_us(&self) -> i64 {
        self.expires_at_us
    }
    pub(super) fn finish(self, committed_at_us: i64) -> crate::IssuerTokenResult<IssuerTokens> {
        let remaining = self
            .expires_at_us
            .checked_sub(committed_at_us)
            .ok_or(crate::IssuerTokenError::Unavailable)?;
        if committed_at_us < self.grant().issued_at_us || remaining < 1_000_000 {
            return Err(crate::IssuerTokenError::Unavailable);
        }
        Ok(IssuerTokens {
            access: self.access,
            id_token: self.id_token,
            expires_in: (remaining / 1_000_000) as u32,
        })
    }
}
impl fmt::Debug for IssuerSignedCode<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuerSignedCode([REDACTED])")
    }
}
/// Wire credentials exist only after the final repository commit. They grant no
/// ordinary local session or application business permissions.
pub struct IssuerTokens {
    access: Secret,
    id_token: Zeroizing<String>,
    expires_in: u32,
}
impl IssuerTokens {
    pub fn access_token(&self) -> &Secret {
        &self.access
    }
    pub fn id_token(&self) -> &str {
        &self.id_token
    }
    pub fn expires_in(&self) -> u32 {
        self.expires_in
    }
}
impl fmt::Debug for IssuerTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuerTokens([REDACTED])")
    }
}
