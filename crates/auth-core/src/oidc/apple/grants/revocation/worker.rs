use super::super::AppleGrantVault;
use super::{
    AppleGrantRevocationJob, AppleGrantRevocationRepository, AppleRevocationConfirmation,
    AppleRevocationFailure as Failure, AppleRevocationHttp, AppleRevocationOutcome as Outcome,
    AppleRevocationRequest,
};
use crate::{
    AppleClientSecretSigner, Error, OAuthConnection, OAuthMixupDefense, OAuthRedirectPolicy,
    OidcConnectionRepository, OidcDocuments, OidcHttp, Result,
};
use std::{sync::Arc, time::Duration};
const REVOCATION_ENDPOINT: &str = "https://appleid.apple.com/auth/revoke";
const REVOCATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Explicit operator composition, not ordinary Apple activation or a user route.
/// It can revoke a disabled sign-in source but cannot issue identity/session proof.
pub struct AppleGrantRevoker {
    source: OAuthConnection,
    documents: OidcDocuments,
    signer: Arc<AppleClientSecretSigner>,
    vault: Arc<AppleGrantVault>,
    repository: Arc<dyn AppleGrantRevocationRepository>,
    http: Arc<dyn AppleRevocationHttp>,
}
impl AppleGrantRevoker {
    pub fn new(
        source: OAuthConnection,
        registry: Arc<dyn OidcConnectionRepository>,
        signer: Arc<AppleClientSecretSigner>,
        vault: Arc<AppleGrantVault>,
        repository: Arc<dyn AppleGrantRevocationRepository>,
        documents: Arc<dyn OidcHttp>,
        http: Arc<dyn AppleRevocationHttp>,
    ) -> Result<Self> {
        if source.issuer() != super::super::super::exchange::ISSUER
            || source.provider_client() != signer.client_id()
            || source.defense() != OAuthMixupDefense::DedicatedRedirect
            || source.redirect_policy() != OAuthRedirectPolicy::Exact
            || !source.redirect().starts_with("https://")
        {
            return Err(Error::InvalidInput);
        }
        let policy = OidcDocuments::new(
            source.clone(),
            &[super::super::super::exchange::ISSUER],
            registry,
            documents,
        )?;
        Ok(Self {
            source,
            documents: policy,
            signer,
            vault,
            repository,
            http,
        })
    }
    pub async fn run_once(&self) -> Result<Outcome> {
        let Some(job) = self.repository.claim_apple_revocation(&self.source).await? else {
            return Ok(Outcome::Idle);
        };
        if !self.matches(&job) {
            return Err(Error::Unavailable);
        }
        let attempt = tokio::time::timeout(REVOCATION_TIMEOUT, self.attempt(&job)).await;
        match attempt {
            Ok(Ok(())) => {
                let confirmed = self
                    .repository
                    .confirm_apple_revocation(&self.source, AppleRevocationConfirmation { job })
                    .await?;
                Ok(if confirmed {
                    Outcome::Confirmed
                } else {
                    Outcome::Stale
                })
            }
            Ok(Err(AttemptFailure::Stale)) => Ok(Outcome::Stale),
            Ok(Err(AttemptFailure::Failed(failure))) => self.defer(&job, failure).await,
            Err(_) => self.defer(&job, Failure::Transport).await,
        }
    }
    fn matches(&self, job: &AppleGrantRevocationJob) -> bool {
        let b = job.envelope().binding();
        (b.realm(), b.connection(), b.client())
            == (
                self.source.realm(),
                self.source.connection(),
                self.source.client(),
            )
    }
    async fn defer(&self, job: &AppleGrantRevocationJob, failure: Failure) -> Result<Outcome> {
        Ok(
            if self
                .repository
                .defer_apple_revocation(&self.source, job, failure)
                .await?
            {
                Outcome::Deferred(failure)
            } else {
                Outcome::Stale
            },
        )
    }
    async fn attempt(
        &self,
        job: &AppleGrantRevocationJob,
    ) -> std::result::Result<(), AttemptFailure> {
        let grant = self
            .vault
            .open_for_revocation(job.envelope())
            .await
            .map_err(|error| {
                AttemptFailure::Failed(if matches!(error, Error::RateLimited) {
                    Failure::Unavailable
                } else {
                    Failure::Configuration
                })
            })?;
        if grant.provider_client != self.source.provider_client() {
            return Err(AttemptFailure::Failed(Failure::Configuration));
        }
        let issued_us = self.check(job).await?;
        let secret = self.signer.issue(issued_us).await.map_err(|error| {
            AttemptFailure::Failed(if matches!(error, Error::Unauthorized) {
                Failure::Configuration
            } else {
                Failure::Unavailable
            })
        })?;
        let secret_expiry = secret.expires_at();
        let request = AppleRevocationRequest::new(self.source.provider_client(), secret, grant)
            .map_err(|_| AttemptFailure::Failed(Failure::Configuration))?;
        // Fixed target policy resolution does not consult sign-in enablement.
        // No discovery, alternate endpoint, credential-selected URL or trust fallback.
        let target = self
            .documents
            .resolve_target(
                url::Url::parse(REVOCATION_ENDPOINT)
                    .map_err(|_| AttemptFailure::Failed(Failure::Configuration))?,
            )
            .await
            .map_err(|_| AttemptFailure::Failed(Failure::Transport))?;
        let now = self.check(job).await?;
        if now < issued_us || i128::from(now) >= i128::from(secret_expiry) * 1_000_000 {
            return Err(AttemptFailure::Failed(Failure::Configuration));
        }
        self.http
            .revoke(&target, &request)
            .await
            .map_err(|_| AttemptFailure::Failed(Failure::Transport))?
            .verify()
            .map_err(AttemptFailure::Failed)
    }
    async fn check(
        &self,
        job: &AppleGrantRevocationJob,
    ) -> std::result::Result<i64, AttemptFailure> {
        let now = self
            .repository
            .check_apple_revocation(&self.source, job)
            .await
            .map_err(|error| {
                if matches!(error, Error::Unauthorized) {
                    AttemptFailure::Stale
                } else {
                    AttemptFailure::Failed(Failure::Unavailable)
                }
            })?;
        if now < job.claimed_us() || now >= job.until_us() {
            return Err(AttemptFailure::Stale);
        }
        Ok(now)
    }
}
enum AttemptFailure {
    Stale,
    Failed(Failure),
}
