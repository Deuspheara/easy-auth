use super::{
    OidcExchangeRepository, OidcVerificationPolicy, VerifiedOidcIdentity,
    input::{self, OidcIdToken},
    work::{self, Attempt, SignatureWork},
};
use crate::{Error, OAuthExchange, OidcDiscovery, OidcDocuments, Result};
use std::{sync::Arc, time::Duration};
use tokio::sync::OwnedSemaphorePermit;

const VERIFY_TIMEOUT: Duration = Duration::from_secs(15);

pub struct OidcTokenVerifier {
    documents: Arc<OidcDocuments>,
    repository: Arc<dyn OidcExchangeRepository>,
    policy: OidcVerificationPolicy,
    work: SignatureWork,
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
            work: SignatureWork::new(),
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
        self.work.lease()
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
        let code_flow = discovery.is_some();
        let discovery = match discovery {
            Some(discovery) => discovery,
            None => self.documents.discovery().await?,
        };
        let observed = if code_flow {
            self.documents.keys_when_admitted(&discovery).await?
        } else {
            self.documents.keys_from_discovery(&discovery, None).await?
        };
        let claims = match work::attempt(&token, observed.clone(), lease.clone()).await? {
            Attempt::Claims(claims) => claims,
            Attempt::UnknownKey => {
                let current = self
                    .documents
                    .keys_from_discovery(&discovery, Some(&observed))
                    .await?;
                // Retain the operation lease through the final authority read;
                // the native retry owns a separate cancellation-safe reference.
                match work::attempt(&token, current, lease.clone()).await? {
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
