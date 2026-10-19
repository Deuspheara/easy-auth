use super::{
    OidcExchangeRepository, OidcVerificationPolicy, VerifiedOidcIdentity,
    claims::Claims,
    input::{self, OidcIdToken},
    keys,
};
use crate::{Error, OAuthExchange, OidcDiscovery, OidcDocuments, OidcJwksDocument, Result};
use std::{sync::Arc, time::Duration};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

const VERIFY_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_VERIFICATIONS: usize = 2;
enum Attempt {
    UnknownKey,
    Claims(Box<Claims>),
}

pub struct OidcTokenVerifier {
    documents: Arc<OidcDocuments>,
    repository: Arc<dyn OidcExchangeRepository>,
    policy: OidcVerificationPolicy,
    workers: Arc<Semaphore>,
}
impl OidcTokenVerifier {
    pub fn new(
        documents: Arc<OidcDocuments>,
        repository: Arc<dyn OidcExchangeRepository>,
        policy: OidcVerificationPolicy,
    ) -> Self {
        Self {
            documents,
            repository,
            policy,
            workers: Arc::new(Semaphore::new(MAX_VERIFICATIONS)),
        }
    }
    pub async fn verify(
        &self,
        exchange: OAuthExchange,
        token: OidcIdToken,
    ) -> Result<VerifiedOidcIdentity> {
        let lease = self.lease_operation()?;
        self.verify_leased(exchange, token, lease, None).await
    }

    pub(in crate::oidc) fn lease_operation(&self) -> Result<Arc<OwnedSemaphorePermit>> {
        Ok(Arc::new(
            self.workers
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::RateLimited)?,
        ))
    }

    pub(in crate::oidc) async fn verify_leased(
        &self,
        exchange: OAuthExchange,
        token: OidcIdToken,
        lease: Arc<OwnedSemaphorePermit>,
        discovery: Option<OidcDiscovery>,
    ) -> Result<VerifiedOidcIdentity> {
        tokio::time::timeout(
            VERIFY_TIMEOUT,
            self.verify_inner(exchange, token, lease, discovery),
        )
        .await
        .map_err(|_| Error::Unavailable)?
    }
    async fn verify_inner(
        &self,
        exchange: OAuthExchange,
        token: OidcIdToken,
        lease: Arc<OwnedSemaphorePermit>,
        discovery: Option<OidcDiscovery>,
    ) -> Result<VerifiedOidcIdentity> {
        if exchange.configuration() != self.documents.connection() {
            return Err(Error::Unauthorized);
        }
        self.repository.check_oidc_exchange(&exchange).await?;
        let header = input::header(&token.0)?;
        if !self.policy.algorithms.contains(&header.alg) {
            return Err(Error::Unauthorized);
        }
        // Reuse validated discovery only inside this bounded operation. In
        // particular, no-store metadata must not cause a second self-throttled
        // fetch after the one-use code has already been exchanged.
        let discovery = match discovery {
            Some(discovery) => discovery,
            None => self.documents.discovery().await?,
        };
        let observed = self.documents.keys_from_discovery(&discovery, None).await?;
        let claims = match attempt(&token, observed.clone(), lease.clone()).await? {
            Attempt::Claims(claims) => claims,
            Attempt::UnknownKey => {
                let current = self
                    .documents
                    .keys_from_discovery(&discovery, Some(&observed))
                    .await?;
                match attempt(&token, current, lease).await? {
                    Attempt::Claims(claims) => claims,
                    Attempt::UnknownKey => return Err(Error::Unauthorized),
                }
            }
        };
        let now_us = self.repository.check_oidc_exchange(&exchange).await?;
        claims.validate(&exchange, &self.policy, now_us)?;
        Ok(VerifiedOidcIdentity::new(exchange, &claims))
    }
}

async fn attempt(
    token: &OidcIdToken,
    document: OidcJwksDocument,
    lease: Arc<OwnedSemaphorePermit>,
) -> Result<Attempt> {
    let token = token.0.clone();
    tokio::task::spawn_blocking(move || {
        // Retain the lease after async cancellation until this native crypto job
        // finishes; repeated timeouts cannot create unbounded detached workers.
        let _lease = lease;
        let header = input::header(&token)?;
        let Some(verifier) = keys::select(&document, &header)? else {
            return Ok(Attempt::UnknownKey);
        };
        let (payload, _) = josekit::jws::deserialize_compact(token.as_bytes(), verifier.as_ref())
            .map_err(|_| Error::Unauthorized)?;
        let payload = Zeroizing::new(payload);
        let claims = serde_json::from_slice(&payload).map_err(|_| Error::Unauthorized)?;
        Ok(Attempt::Claims(claims))
    })
    .await
    .map_err(|_| Error::Unavailable)?
}
