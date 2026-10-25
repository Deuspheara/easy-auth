mod completion;
mod preparation;

use crate::Postgres;
use async_trait::async_trait;
use auth_core::{
    IssuerCodeRedemption, IssuerSignedCode, IssuerTokenPreparationData, IssuerTokenRepository,
    IssuerTokenResult,
};
#[async_trait]
impl IssuerTokenRepository for Postgres {
    async fn prepare_issuer_token(
        &self,
        request: &IssuerCodeRedemption<'_>,
    ) -> IssuerTokenResult<IssuerTokenPreparationData> {
        preparation::prepare(self, request).await
    }
    async fn commit_issuer_token(&self, signed: &IssuerSignedCode<'_>) -> IssuerTokenResult<i64> {
        completion::commit(self, signed).await
    }
}
