use super::OidcMappedIdentity;
use crate::{Error, OAuthPurpose, Result};
use async_trait::async_trait;
use std::sync::Arc;

/// Signed provider authentication, never local token/session creation time.
pub const MAX_OIDC_DELETION_AUTH_AGE_SECONDS: u64 = 300;

#[async_trait]
pub trait OidcAccountDeletionRepository: Send + Sync {
    /// Consume the purpose-bound proof. Recheck exact current source, original
    /// owner/session/subject, genuine signed freshness and every original cap
    /// under locks; erase account/audit/notice state atomically before returning.
    /// No remote I/O or weaker fallback belongs in this transaction.
    async fn finish_oidc_account_deletion(&self, identity: OidcMappedIdentity) -> Result<()>;
}

/// Explicit destructive use case. The consuming UI must obtain deliberate
/// confirmation; a callback GET or a sign-in proof must never invoke deletion.
pub struct OidcAccountDeletion {
    repository: Arc<dyn OidcAccountDeletionRepository>,
}

impl OidcAccountDeletion {
    pub fn new(repository: Arc<dyn OidcAccountDeletionRepository>) -> Self {
        Self { repository }
    }

    pub async fn finish(&self, identity: OidcMappedIdentity) -> Result<()> {
        if !matches!(
            identity.identity().purpose(),
            OAuthPurpose::DeleteProviderAccount { .. }
        ) || identity.identity().authenticated_at().is_none()
        {
            return Err(Error::Unauthorized);
        }
        self.repository.finish_oidc_account_deletion(identity).await
    }
}
