use super::SamlMappedIdentity;
use crate::{Result, Secret, User, Verifier};
use async_trait::async_trait;
use std::sync::Arc;

#[async_trait]
pub trait SamlIdentityRepository: Send + Sync {
    /// Recheck exact current source/policy and original/signed caps; reserve both
    /// replay IDs and resolve identity/session/audit in one local transaction.
    /// Signature verification and network I/O must finish before that transaction.
    async fn finish_saml_identity(
        &self,
        identity: SamlMappedIdentity,
        session: Verifier,
    ) -> Result<User>;
}

pub struct SamlSignIn {
    repository: Arc<dyn SamlIdentityRepository>,
}
impl SamlSignIn {
    pub fn new(repository: Arc<dyn SamlIdentityRepository>) -> Self {
        Self { repository }
    }
    pub async fn finish(&self, identity: SamlMappedIdentity) -> Result<(User, Secret)> {
        let session = Secret::generate()?;
        let user = self
            .repository
            .finish_saml_identity(identity, session.verifier())
            .await?;
        Ok((user, session))
    }
}
