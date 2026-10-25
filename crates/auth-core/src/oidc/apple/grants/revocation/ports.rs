use super::{
    AppleGrantRevocationJob, AppleRevocationConfirmation, AppleRevocationRequest,
    AppleRevocationResponse,
};
use crate::{OAuthConnection, OidcTarget, Result};
use async_trait::async_trait;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppleRevocationFailure {
    Transport,
    Provider,
    Configuration,
    Unavailable,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppleRevocationOutcome {
    Idle,
    Confirmed,
    Deferred(AppleRevocationFailure),
    Stale,
}
#[async_trait]
pub trait AppleGrantRevocationRepository: Send + Sync {
    /// Scope by immutable source IDs and exact provider client; disabled sign-in
    /// is not permission to lose already queued revocation work. No network locks.
    async fn claim_apple_revocation(
        &self,
        source: &OAuthConnection,
    ) -> Result<Option<AppleGrantRevocationJob>>;
    async fn check_apple_revocation(
        &self,
        source: &OAuthConnection,
        job: &AppleGrantRevocationJob,
    ) -> Result<i64>;
    async fn confirm_apple_revocation(
        &self,
        source: &OAuthConnection,
        confirmation: AppleRevocationConfirmation,
    ) -> Result<bool>;
    async fn defer_apple_revocation(
        &self,
        source: &OAuthConnection,
        job: &AppleGrantRevocationJob,
        failure: AppleRevocationFailure,
    ) -> Result<bool>;
}
#[async_trait]
pub trait AppleRevocationHttp: Send + Sync {
    /// One bounded protected POST to the checked/pinned fixed Apple target.
    /// No proxies, redirects, transport retries, cookies or raw diagnostics.
    async fn revoke(
        &self,
        target: &OidcTarget,
        request: &AppleRevocationRequest,
    ) -> Result<AppleRevocationResponse>;
}
