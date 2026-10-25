//! Concrete bounded JOSE verification work; no identity or transaction proof.
use super::{
    claims::Claims,
    input::{self, OidcIdToken},
    keys,
};
use crate::{Error, OidcJwksDocument, Result};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

const MAX_VERIFICATIONS: usize = 2;
pub(super) enum Attempt {
    UnknownKey,
    Claims(Box<Claims>),
}
pub(super) struct SignatureWork {
    workers: Arc<Semaphore>,
}
impl SignatureWork {
    pub(super) fn new() -> Self {
        Self {
            workers: Arc::new(Semaphore::new(MAX_VERIFICATIONS)),
        }
    }
    pub(super) fn lease(&self) -> Result<Arc<OwnedSemaphorePermit>> {
        Ok(Arc::new(
            self.workers
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::RateLimited)?,
        ))
    }
}

pub(super) async fn attempt(
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
