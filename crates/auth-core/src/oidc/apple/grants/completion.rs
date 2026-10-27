use super::AppleMappedGrant;
use crate::{Error, LinkedProvider, OAuthPurpose, Result, Secret, User, Verifier};
use async_trait::async_trait;
use std::sync::Arc;

#[async_trait]
pub trait AppleGrantRepository: Send + Sync {
    /// Same existing proof/policy/ownership/session checks, plus atomic protected
    /// capture on the actual resolved identity. No remote I/O inside transaction.
    async fn finish_apple_grant_sign_in(
        &self,
        grant: AppleMappedGrant,
        session: Verifier,
    ) -> Result<User>;
    async fn finish_apple_grant_link(
        &self,
        grant: AppleMappedGrant,
        current: Verifier,
    ) -> Result<LinkedProvider>;
}
pub struct AppleGrantSignIn {
    repository: Arc<dyn AppleGrantRepository>,
}
impl AppleGrantSignIn {
    pub fn new(repository: Arc<dyn AppleGrantRepository>) -> Self {
        Self { repository }
    }
    pub async fn finish(&self, grant: AppleMappedGrant) -> Result<(User, Secret)> {
        if !matches!(grant.identity().identity().purpose(), OAuthPurpose::SignIn) {
            return Err(Error::Unauthorized);
        }
        let session = Secret::generate()?;
        let user = self
            .repository
            .finish_apple_grant_sign_in(grant, session.verifier())
            .await?;
        Ok((user, session))
    }
}
pub struct AppleGrantLinking {
    repository: Arc<dyn AppleGrantRepository>,
}
impl AppleGrantLinking {
    pub fn new(repository: Arc<dyn AppleGrantRepository>) -> Self {
        Self { repository }
    }
    pub async fn finish(
        &self,
        grant: AppleMappedGrant,
        current: &Secret,
    ) -> Result<LinkedProvider> {
        match grant.identity().identity().purpose() {
            OAuthPurpose::Link { user, session }
                if !user.is_nil() && *session == current.verifier() => {}
            _ => return Err(Error::Unauthorized),
        }
        self.repository
            .finish_apple_grant_link(grant, current.verifier())
            .await
    }
}
