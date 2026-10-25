mod completion;
mod notices;
mod unlink;
use crate::Postgres;
use async_trait::async_trait;
use auth_core::{LinkedProvider, OidcIdentityLinkRepository, OidcMappedIdentity, Result, Verifier};
use uuid::Uuid;

#[async_trait]
impl OidcIdentityLinkRepository for Postgres {
    async fn finish_oidc_identity_link(
        &self,
        identity: OidcMappedIdentity,
        current: Verifier,
    ) -> Result<LinkedProvider> {
        completion::finish(self, identity, current).await
    }
    async fn unlink_oidc_identity(
        &self,
        realm: Uuid,
        current: Verifier,
        identity: Uuid,
    ) -> Result<()> {
        unlink::finish(self, realm, current, identity).await
    }
}
