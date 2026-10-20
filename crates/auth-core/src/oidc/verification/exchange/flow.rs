use super::super::{
    OidcExchangeRepository, OidcTokenVerifier, OidcVerificationPolicy, VerifiedOidcIdentity,
};
use super::{
    OidcAuthorizationCode, OidcAuthorizationUrl, OidcClientAuthentication, OidcTokenRequest,
    OidcTokenResponse,
};
use crate::{Error, OAuthExchange, OAuthStart, OidcDocuments, OidcTarget, Result};
use async_trait::async_trait;
use std::{sync::Arc, time::Duration};
use tokio::sync::OwnedSemaphorePermit;

const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

#[async_trait]
pub trait OidcTokenHttp: Send + Sync {
    /// One protected POST to this checked/pinned target. No redirects, proxies,
    /// retries, cookies or diagnostics containing headers/body/foreign causes.
    async fn post(
        &self,
        target: &OidcTarget,
        request: &OidcTokenRequest,
    ) -> Result<OidcTokenResponse>;
}

pub struct OidcCodeExchange {
    documents: Arc<OidcDocuments>,
    repository: Arc<dyn OidcExchangeRepository>,
    authentication: OidcClientAuthentication,
    http: Arc<dyn OidcTokenHttp>,
    verifier: OidcTokenVerifier,
}
impl OidcCodeExchange {
    pub fn new(
        documents: Arc<OidcDocuments>,
        repository: Arc<dyn OidcExchangeRepository>,
        policy: OidcVerificationPolicy,
        authentication: OidcClientAuthentication,
        http: Arc<dyn OidcTokenHttp>,
    ) -> Self {
        let verifier = OidcTokenVerifier::new(documents.clone(), repository.clone(), policy);
        Self {
            documents,
            repository,
            authentication,
            http,
            verifier,
        }
    }
    /// Start must come from the matching configured OAuthTransactions. Retain its
    /// proof in protected browser transport, then consume the actual callback.
    pub async fn authorization_url(
        &self,
        start: &OAuthStart,
        scopes: &[&str],
    ) -> Result<OidcAuthorizationUrl> {
        self.authorization(start, scopes, false).await
    }
    /// Request fresh provider authentication without accepting arbitrary extra
    /// parameters. The request is not proof of freshness: consumers must require
    /// and validate signed auth_time and their exact purpose/context at commit.
    pub async fn reauthentication_url(
        &self,
        start: &OAuthStart,
        scopes: &[&str],
    ) -> Result<OidcAuthorizationUrl> {
        self.authorization(start, scopes, true).await
    }
    async fn authorization(
        &self,
        start: &OAuthStart,
        scopes: &[&str],
        reauthenticate: bool,
    ) -> Result<OidcAuthorizationUrl> {
        let _lease = self.verifier.lease_operation()?;
        let discovery = self.documents.discovery_when_admitted().await?;
        self.check_provider(&discovery)?;
        OidcAuthorizationUrl::new(
            &discovery,
            self.documents.connection(),
            start,
            scopes,
            reauthenticate,
        )
    }
    pub async fn exchange(
        &self,
        exchange: OAuthExchange,
        code: OidcAuthorizationCode,
    ) -> Result<VerifiedOidcIdentity> {
        let lease = self.verifier.lease_operation()?;
        tokio::time::timeout(EXCHANGE_TIMEOUT, self.exchange_inner(exchange, code, lease))
            .await
            .map_err(|_| Error::Unavailable)?
    }
    async fn exchange_inner(
        &self,
        exchange: OAuthExchange,
        code: OidcAuthorizationCode,
        lease: Arc<OwnedSemaphorePermit>,
    ) -> Result<VerifiedOidcIdentity> {
        if exchange.configuration() != self.documents.connection() {
            return Err(Error::Unauthorized);
        }
        self.repository.check_oidc_exchange(&exchange).await?;
        let discovery = self.documents.discovery_when_admitted().await?;
        self.check_provider(&discovery)?;
        let url = url::Url::parse(discovery.token_endpoint()).map_err(|_| Error::Unavailable)?;
        super::request::validate_endpoint(&url)?;
        let target = self.documents.resolve_target(url).await?;
        // DNS can spend the original proof/session's remaining lifetime. Recheck
        // before any code/client credential is sent, with no DB lock over I/O.
        self.repository.check_oidc_exchange(&exchange).await?;
        let request = OidcTokenRequest::new(&exchange, code, &self.authentication);
        let response = self.http.post(&target, &request).await?;
        let token = response.id_token()?;
        self.verifier
            .verify_leased(exchange, token, lease, Some(discovery))
            .await
    }
    fn check_provider(&self, discovery: &crate::OidcDiscovery) -> Result<()> {
        if !discovery.supports_s256()
            || !discovery
                .token_authentication_methods()
                .iter()
                .any(|method| method == self.authentication.method())
        {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
}
