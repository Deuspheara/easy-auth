use crate::Postgres;
use async_trait::async_trait;
use auth_core::{IssuerAuthority, IssuerMetadataRepository, IssuerPublicKey, Result};
#[async_trait]
impl IssuerMetadataRepository for Postgres {
    async fn published_issuer_keys(
        &self,
        authority: &IssuerAuthority,
    ) -> Result<Vec<IssuerPublicKey>> {
        self.issuer_public_keys(authority).await
    }
}
