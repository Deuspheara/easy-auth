use super::OidcMappedIdentity;
use crate::{Error, LinkedProvider, OAuthPurpose, Result, Secret, Verifier};
use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

#[async_trait]
pub trait OidcIdentityLinkRepository: Send + Sync {
    /// Consume the original Link proof. Recheck target/current source, exact
    /// owner/session, subject uniqueness and original caps under locks; commit
    /// identity, finite audit and verified-contact notice together. No session,
    /// contact, account-policy mutation, email matching or remote I/O is allowed.
    async fn finish_oidc_identity_link(
        &self,
        identity: OidcMappedIdentity,
        current: Verifier,
    ) -> Result<LinkedProvider>;

    /// Require a genuinely fresh retained authentication method. Never remove the
    /// caller's own OIDC source. Recheck realm/owner/target, preserve original caps,
    /// invalidate target sessions and install the existing scoped cooldown before
    /// atomic audit/notice commit. This is not remote provider grant revocation.
    async fn unlink_oidc_identity(
        &self,
        realm: Uuid,
        current: Verifier,
        identity: Uuid,
    ) -> Result<()>;
}

/// Explicit owner-authorized identity mutation; neither operation issues a session.
pub struct OidcIdentityLinking {
    repository: Arc<dyn OidcIdentityLinkRepository>,
}
impl OidcIdentityLinking {
    pub fn new(repository: Arc<dyn OidcIdentityLinkRepository>) -> Self {
        Self { repository }
    }

    pub async fn finish(
        &self,
        identity: OidcMappedIdentity,
        current: &Secret,
    ) -> Result<LinkedProvider> {
        match identity.identity().purpose() {
            OAuthPurpose::Link { user, session }
                if !user.is_nil() && *session == current.verifier() => {}
            _ => return Err(Error::Unauthorized),
        }
        self.repository
            .finish_oidc_identity_link(identity, current.verifier())
            .await
    }

    /// The caller must deliberately confirm unlinking and reauthenticate with a
    /// method it retains. A public inventory UUID proves neither ownership nor freshness.
    pub async fn unlink(&self, realm: Uuid, current: &Secret, identity: Uuid) -> Result<()> {
        if realm.is_nil() || identity.is_nil() {
            return Err(Error::InvalidInput);
        }
        self.repository
            .unlink_oidc_identity(realm, current.verifier(), identity)
            .await
    }
}
