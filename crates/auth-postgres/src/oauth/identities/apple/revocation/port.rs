use crate::Postgres;
use async_trait::async_trait;
use auth_core::{
    AppleGrantRevocationJob, AppleGrantRevocationRepository, AppleRevocationConfirmation,
    AppleRevocationFailure, OAuthConnection, Result,
};
#[async_trait]
impl AppleGrantRevocationRepository for Postgres {
    async fn claim_apple_revocation(
        &self,
        source: &OAuthConnection,
    ) -> Result<Option<AppleGrantRevocationJob>> {
        super::claim::claim(self, source).await
    }
    async fn check_apple_revocation(
        &self,
        source: &OAuthConnection,
        job: &AppleGrantRevocationJob,
    ) -> Result<i64> {
        super::claim::check(self, source, job).await
    }
    async fn confirm_apple_revocation(
        &self,
        source: &OAuthConnection,
        confirmation: AppleRevocationConfirmation,
    ) -> Result<bool> {
        super::completion::confirm(self, source, confirmation).await
    }
    async fn defer_apple_revocation(
        &self,
        source: &OAuthConnection,
        job: &AppleGrantRevocationJob,
        failure: AppleRevocationFailure,
    ) -> Result<bool> {
        super::completion::defer(self, source, job, failure).await
    }
}
