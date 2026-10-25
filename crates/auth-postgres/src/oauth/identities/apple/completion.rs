use crate::Postgres;
use async_trait::async_trait;
use auth_core::{AppleGrantRepository, AppleMappedGrant, LinkedProvider, Result, User, Verifier};
#[async_trait]
impl AppleGrantRepository for Postgres {
    async fn finish_apple_grant_sign_in(
        &self,
        grant: AppleMappedGrant,
        session: Verifier,
    ) -> Result<User> {
        let (mapped, capture) = grant.into_parts();
        super::super::completion::finish(self, mapped, session, Some(capture)).await
    }
    async fn finish_apple_grant_link(
        &self,
        grant: AppleMappedGrant,
        current: Verifier,
    ) -> Result<LinkedProvider> {
        let (mapped, capture) = grant.into_parts();
        super::super::linking::finish_apple_capture(self, mapped, current, capture).await
    }
}
