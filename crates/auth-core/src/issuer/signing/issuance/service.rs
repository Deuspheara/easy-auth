use super::{
    IssuerSignedCode, IssuerTokenRepository, IssuerTokens, claims, native, proof::StagedData,
};
use crate::{
    Error, IssuerAuthority, IssuerAuthorization, IssuerClientAuthentication, IssuerCodeRedemption,
    IssuerPkceVerifier, IssuerSigningKey, IssuerTokenError, IssuerTokenResult, Secret,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use uuid::Uuid;

const MAX_SIGNING_OPERATIONS: usize = 2;
const TOKEN_OPERATION_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_CODE_SNAPSHOT_BYTES: usize = 16 * 1024;
const MIN_TOKEN_REMAINING_US: i64 = 1_000_000;

pub struct IssuerTokenIssuer {
    authorization: IssuerAuthorization,
    repository: Arc<dyn IssuerTokenRepository>,
    keys: Vec<Arc<IssuerSigningKey>>,
    capacity: Arc<Semaphore>,
}
impl IssuerTokenIssuer {
    pub fn new(
        authority: IssuerAuthority,
        repository: Arc<dyn IssuerTokenRepository>,
        keys: Vec<Arc<IssuerSigningKey>>,
    ) -> crate::Result<Self> {
        if keys.is_empty()
            || keys.len() as i64 > super::super::MAX_ISSUER_PUBLISHED_KEYS
            || keys
                .iter()
                .enumerate()
                .any(|(i, key)| keys[..i].iter().any(|other| other.id() == key.id()))
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            authorization: IssuerAuthorization::new(authority, repository.clone()),
            repository,
            keys,
            capacity: Arc::new(Semaphore::new(MAX_SIGNING_OPERATIONS)),
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
        let lease = Arc::new(
            self.capacity
                .clone()
                .try_acquire_owned()
                .map_err(|_| IssuerTokenError::RateLimited)?,
        );
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
        if staged.data.signing.authority() != self.authority()
            || staged.data.code_snapshot.is_empty()
            || staged.data.code_snapshot.len() > MAX_CODE_SNAPSHOT_BYTES
        {
            return Err(IssuerTokenError::Unavailable);
        }
        let publication = staged.data.signing.publication();
        let issued = staged.data.grant.issued_at_us;
        if issued < publication.sign_from_us() || issued >= publication.sign_until_us() {
            return Err(IssuerTokenError::Unavailable);
        }
        let key = self
            .keys
            .iter()
            .find(|key| key.id() == publication.key().id())
            .ok_or(IssuerTokenError::Unavailable)?
            .clone();
        if key.public_key()? != *publication.key() {
            return Err(IssuerTokenError::Unavailable);
        }
        let policy_expiry = issued
            .checked_add(super::super::ISSUER_ID_TOKEN_LIFETIME_SECONDS * 1_000_000)
            .ok_or(IssuerTokenError::Unavailable)?;
        let expiry = staged
            .data
            .grant
            .expires_at_us
            .min(publication.sign_until_us())
            .min(publication.verify_until_us())
            .min(policy_expiry)
            / 1_000_000
            * 1_000_000;
        if expiry - issued < MIN_TOKEN_REMAINING_US {
            return Err(IssuerTokenError::InvalidGrant);
        }
        let payload = claims::payload(&staged, &client, expiry)?;
        let access = Secret::generate()?;
        let id_token = native::sign(key, payload, lease.clone()).await?;
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
