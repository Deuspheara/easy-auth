use super::IssuerSignedCode;
use crate::{
    IssuerAuthorizationRepository, IssuerCodeRedemption, IssuerGrantData, IssuerSigningSnapshot,
    IssuerTokenResult,
};
use async_trait::async_trait;

/// Trusted repository facts for staging only. They are not a consumed grant or
/// signed proof. The complete approved-row snapshot is private port data.
pub struct IssuerTokenPreparationData {
    pub signing: IssuerSigningSnapshot,
    pub grant: IssuerGrantData,
    pub code_snapshot: String,
}
#[async_trait]
pub trait IssuerTokenRepository: IssuerAuthorizationRepository {
    /// Authenticate the current client, then lock current signing/source/owner/
    /// session/code and capture original facts. Release all locks without consume.
    async fn prepare_issuer_token(
        &self,
        request: &IssuerCodeRedemption<'_>,
    ) -> IssuerTokenResult<IssuerTokenPreparationData>;
    /// Revalidate the exact signed staging tuple, all original/current caps and
    /// credentials; consume code, persist hash-only access and audit atomically.
    /// Return the final database time only after successful commit.
    async fn commit_issuer_token(&self, signed: &IssuerSignedCode<'_>) -> IssuerTokenResult<i64>;
}
