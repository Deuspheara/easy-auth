use super::super::{IssuerTokenIssuer, engine::SigningEngine};
use super::{
    IssuerNativeSignedCode, IssuerNativeTokenRepository, IssuerNativeTokens, proof::NativeStaged,
};
use crate::{
    IssuerAuthority, IssuerAuthorization, IssuerClientAuthentication, IssuerCodeRedemption,
    IssuerPkceVerifier, IssuerRedirectProfile, IssuerTokenError, IssuerTokenResult, Secret,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::OwnedSemaphorePermit;
use uuid::Uuid;

const TOKEN_OPERATION_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_CONSENT_SNAPSHOT_BYTES: usize = 16 * 1024;

pub struct IssuerNativeTokenIssuer {
    authorization: IssuerAuthorization,
    repository: Arc<dyn IssuerNativeTokenRepository>,
    engine: Arc<SigningEngine>,
}
impl IssuerNativeTokenIssuer {
    /// Share the existing validated key set and bounded signing capacity.
    /// This does not mount routes or enable native policy/issuer configuration.
    pub fn new(
        signer: &IssuerTokenIssuer,
        repository: Arc<dyn IssuerNativeTokenRepository>,
    ) -> Self {
        Self {
            authorization: IssuerAuthorization::new(signer.authority().clone(), repository.clone()),
            repository,
            engine: signer.engine.clone(),
        }
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
    ) -> IssuerTokenResult<IssuerNativeTokens> {
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
        lease: Arc<OwnedSemaphorePermit>,
    ) -> IssuerTokenResult<IssuerNativeTokens> {
        let client = self
            .authorization
            .client_for_token_operation(authentication, source)
            .await?;
        if client.redirect_profile() != IssuerRedirectProfile::NativeRefreshLoopback {
            return Err(IssuerTokenError::InvalidClient);
        }
        let request = IssuerCodeRedemption {
            authority: self.authority(),
            client: &client,
            authentication,
            code: code.verifier(),
            redirect_uri,
            pkce: pkce.s256_digest(),
        };
        let staged = NativeStaged {
            data: self
                .repository
                .prepare_issuer_native_token(&request)
                .await?,
        };
        let data = &staged.data;
        data.token
            .grant
            .validate_common(self.authority(), &client)?;
        data.consent
            .validate(
                self.authority(),
                &client,
                data.token.grant.expires_at_us,
                true,
            )
            .map_err(|_| IssuerTokenError::Unavailable)?;
        if data.consent_authorization != data.token.grant.authorization
            || data
                .consent
                .approved_at_us
                .ok_or(IssuerTokenError::Unavailable)?
                > data.token.grant.issued_at_us
            || data.consent_snapshot.is_empty()
            || data.consent_snapshot.len() > MAX_CONSENT_SNAPSHOT_BYTES
        {
            return Err(IssuerTokenError::Unavailable);
        }
        let signature = self
            .engine
            .prepare(self.authority(), &data.token, &client)?;
        let access = Secret::generate()?;
        let refresh = Secret::generate()?;
        let (id_token, expires) = signature.sign(lease.clone()).await?;
        let signed = IssuerNativeSignedCode {
            request,
            staged,
            family: Uuid::new_v4(),
            access_id: Uuid::new_v4(),
            access,
            refresh,
            id_token,
            expires,
        };
        let committed = self.repository.commit_issuer_native_token(&signed).await?;
        drop(lease);
        signed.finish(committed)
    }
}
