use super::SamlVerifiedDeletion;
use crate::Result;
use async_trait::async_trait;
use std::sync::Arc;

#[async_trait]
pub trait SamlAccountDeletionRepository: Send + Sync {
    /// Recheck exact current policy, initiating owner/session/identity and signed
    /// subject/freshness. Reserve replay and atomically erase local authority,
    /// audit/contact notice and cooldown, retaining every cap through final commit.
    /// Signature verification and remote I/O finish before authority locks.
    async fn finish_saml_account_deletion(&self, proof: SamlVerifiedDeletion) -> Result<()>;
}

/// Explicit destructive operation. Consuming transport must obtain deliberate
/// confirmation. Verification or a delivery callback alone may never invoke it.
pub struct SamlAccountDeletion {
    repository: Arc<dyn SamlAccountDeletionRepository>,
}
impl SamlAccountDeletion {
    pub fn new(repository: Arc<dyn SamlAccountDeletionRepository>) -> Self {
        Self { repository }
    }
    pub async fn finish(&self, proof: SamlVerifiedDeletion) -> Result<()> {
        self.repository.finish_saml_account_deletion(proof).await
    }
}
