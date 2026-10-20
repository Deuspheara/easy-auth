use super::OidcMappedIdentity;
use crate::{Error, OAuthPurpose, Result, Secret, User, Verifier};
use async_trait::async_trait;
use std::sync::Arc;

#[async_trait]
pub trait OidcIdentityRepository: Send + Sync {
    /// Consume the opaque proof exactly once. Recheck current configuration,
    /// policy, original deadline and ownership, then atomically resolve/provision
    /// identity, session and audit. No network call belongs in this transaction.
    async fn finish_oidc_identity(
        &self,
        identity: OidcMappedIdentity,
        session: Verifier,
    ) -> Result<User>;
}

pub struct OidcSignIn {
    repository: Arc<dyn OidcIdentityRepository>,
}

impl OidcSignIn {
    pub fn new(repository: Arc<dyn OidcIdentityRepository>) -> Self {
        Self { repository }
    }

    pub async fn finish(&self, identity: OidcMappedIdentity) -> Result<(User, Secret)> {
        if !matches!(identity.identity().purpose(), OAuthPurpose::SignIn) {
            return Err(Error::Unauthorized);
        }
        let session = Secret::generate()?;
        let user = self
            .repository
            .finish_oidc_identity(identity, session.verifier())
            .await?;
        Ok((user, session))
    }
}
