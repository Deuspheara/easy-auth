//! Initial concrete native signature -> atomic family/hash/code/audit commit.
mod completion;
mod preparation;
mod writing;

use crate::Postgres;
use async_trait::async_trait;
use auth_core::{
    IssuerCodeRedemption, IssuerNativeSignedCode, IssuerNativeTokenCommit,
    IssuerNativeTokenPreparationData, IssuerNativeTokenRepository, IssuerTokenResult,
};

#[async_trait]
impl IssuerNativeTokenRepository for Postgres {
    async fn prepare_issuer_native_token(
        &self,
        request: &IssuerCodeRedemption<'_>,
    ) -> IssuerTokenResult<IssuerNativeTokenPreparationData> {
        preparation::prepare(self, request).await
    }
    async fn commit_issuer_native_token(
        &self,
        signed: &IssuerNativeSignedCode<'_>,
    ) -> IssuerTokenResult<IssuerNativeTokenCommit> {
        completion::commit(self, signed).await
    }
}
