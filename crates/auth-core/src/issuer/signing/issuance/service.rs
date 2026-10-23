use super::{IssuerSignedCode, IssuerTokenRepository, IssuerTokens, proof::StagedData};
use crate::{
    IssuerAuthority, IssuerAuthorization, IssuerClientAuthentication, IssuerCodeRedemption,
    IssuerPkceVerifier, IssuerSigningKey, IssuerTokenError, IssuerTokenResult, Secret,
};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

const TOKEN_OPERATION_TIMEOUT: Duration = Duration::from_secs(15);

pub struct IssuerTokenIssuer {
    authorization: IssuerAuthorization,
    repository: Arc<dyn IssuerTokenRepository>,
    pub(super) engine: Arc<super::engine::SigningEngine>,
}
impl IssuerTokenIssuer {
    pub fn new(
        authority: IssuerAuthority,
        repository: Arc<dyn IssuerTokenRepository>,
        keys: Vec<Arc<IssuerSigningKey>>,
    ) -> crate::Result<Self> {
        Ok(Self {
            authorization: IssuerAuthorization::new(authority, repository.clone()),
            repository,
            engine: Arc::new(super::engine::SigningEngine::new(keys)?),
        })
    }
    pub fn authority(&self) -> &IssuerAuthority {
        self.authorization.authority()
    }
    pub async fn exchange(
        &self,
        authentication: &IssuerClientAuthentication,
        code: &Secret,
        redirect_uri: &str,
        pkce: &IssuerPkceVerifier,
        source: &str,
    ) -> IssuerTokenResult<IssuerTokens> {
        let lease = self.engine.acquire()?;
        tokio::time::timeout(
            TOKEN_OPERATION_TIMEOUT,
            self.issue(authentication, code, redirect_uri, pkce, source, lease),
        )
        .await
        .map_err(|_| IssuerTokenError::Unavailable)?
    }
    async fn issue(
        &self,
        authentication: &IssuerClientAuthentication,
        code: &Secret,
        redirect_uri: &str,
        pkce: &IssuerPkceVerifier,
        source: &str,
        lease: Arc<tokio::sync::OwnedSemaphorePermit>,
    ) -> IssuerTokenResult<IssuerTokens> {
        let client = self
            .authorization
            .client_for_token_operation(authentication, source)
            .await?;
        let request = IssuerCodeRedemption {
            authority: self.authority(),
            client: &client,
            authentication,
            code: code.verifier(),
            redirect_uri,
            pkce: pkce.s256_digest(),
        };
        let staged = StagedData {
            data: self.repository.prepare_issuer_token(&request).await?,
        };
        staged.data.grant.validate(self.authority(), &client)?;
        let signature = self
            .engine
            .prepare(self.authority(), &staged.data, &client)?;
        let access = Secret::generate()?;
        let (id_token, expiry) = signature.sign(lease.clone()).await?;
        let signed = IssuerSignedCode {
            request,
            staged,
            token_id: Uuid::new_v4(),
            access,
            id_token,
            expires_at_us: expiry,
        };
        let committed_at = self.repository.commit_issuer_token(&signed).await?;
        drop(lease);
        signed.finish(committed_at)
    }
}
