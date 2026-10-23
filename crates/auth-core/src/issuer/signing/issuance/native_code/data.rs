use super::IssuerNativeSignedCode;
use crate::{
    IssuerCodeRedemption, IssuerNativeAuthorizationRepository, IssuerNativeConsentData,
    IssuerTokenPreparationData, IssuerTokenResult,
};
use async_trait::async_trait;
use uuid::Uuid;

/// Trusted staging facts only. Neither these facts nor the captured JSON
/// snapshots are signing authority, consumed code or a native refresh credential.
pub struct IssuerNativeTokenPreparationData {
    pub token: IssuerTokenPreparationData,
    pub consent: IssuerNativeConsentData,
    pub consent_authorization: Uuid,
    pub consent_snapshot: String,
}
pub struct IssuerNativeTokenCommit {
    pub committed_at_us: i64,
    pub refresh_expires_at_us: i64,
}
#[async_trait]
pub trait IssuerNativeTokenRepository: IssuerNativeAuthorizationRepository {
    async fn prepare_issuer_native_token(
        &self,
        request: &IssuerCodeRedemption<'_>,
    ) -> IssuerTokenResult<IssuerNativeTokenPreparationData>;
    /// Current client/policy/key/source/owner/code/consent and exact snapshots
    /// must still hold. Create family/hash-only credentials and consume code
    /// with typed audit atomically, then return the final database clock.
    async fn commit_issuer_native_token(
        &self,
        signed: &IssuerNativeSignedCode<'_>,
    ) -> IssuerTokenResult<IssuerNativeTokenCommit>;
}
