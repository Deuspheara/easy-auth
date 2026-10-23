use super::{IssuerTokenPreparationData, claims, native};
use crate::{
    Error, IssuerAuthority, IssuerClientRegistration, IssuerSigningKey, IssuerTokenError,
    IssuerTokenResult,
};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

const MAX_SIGNING_OPERATIONS: usize = 2;
const MAX_CODE_SNAPSHOT_BYTES: usize = 16 * 1024;
const MIN_TOKEN_REMAINING_US: i64 = 1_000_000;

pub(super) struct SigningEngine {
    keys: Vec<Arc<IssuerSigningKey>>,
    capacity: Arc<Semaphore>,
}
impl SigningEngine {
    pub(super) fn new(keys: Vec<Arc<IssuerSigningKey>>) -> crate::Result<Self> {
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
            keys,
            capacity: Arc::new(Semaphore::new(MAX_SIGNING_OPERATIONS)),
        })
    }
    pub(super) fn acquire(&self) -> IssuerTokenResult<Arc<OwnedSemaphorePermit>> {
        Ok(Arc::new(
            self.capacity
                .clone()
                .try_acquire_owned()
                .map_err(|_| IssuerTokenError::RateLimited)?,
        ))
    }
    pub(super) fn prepare(
        &self,
        authority: &IssuerAuthority,
        data: &IssuerTokenPreparationData,
        client: &IssuerClientRegistration,
    ) -> IssuerTokenResult<PreparedSignature> {
        if data.signing.authority() != authority
            || data.code_snapshot.is_empty()
            || data.code_snapshot.len() > MAX_CODE_SNAPSHOT_BYTES
        {
            return Err(IssuerTokenError::Unavailable);
        }
        let publication = data.signing.publication();
        let issued = data.grant.issued_at_us;
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
        let expiry = data
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
        let payload = claims::payload(authority, &data.grant, client, expiry)?;
        Ok(PreparedSignature {
            key,
            payload,
            expiry,
        })
    }
}

/// Concrete one-use RS256 input, private to issuance; no protocol proof or wire output.
pub(super) struct PreparedSignature {
    key: Arc<IssuerSigningKey>,
    payload: Zeroizing<Vec<u8>>,
    expiry: i64,
}
impl PreparedSignature {
    pub(super) async fn sign(
        self,
        lease: Arc<OwnedSemaphorePermit>,
    ) -> IssuerTokenResult<(Zeroizing<String>, i64)> {
        let id_token = native::sign(self.key, self.payload, lease).await?;
        Ok((id_token, self.expiry))
    }
}
