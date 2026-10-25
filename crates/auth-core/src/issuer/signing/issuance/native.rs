use crate::{IssuerSigningKey, IssuerTokenError, IssuerTokenResult};
use std::sync::Arc;
use tokio::sync::OwnedSemaphorePermit;
use zeroize::Zeroizing;

pub(super) async fn sign(
    key: Arc<IssuerSigningKey>,
    payload: Zeroizing<Vec<u8>>,
    lease: Arc<OwnedSemaphorePermit>,
) -> IssuerTokenResult<Zeroizing<String>> {
    tokio::task::spawn_blocking(move || {
        // Cancellation cannot release native capacity while OpenSSL still runs.
        let result = key.sign(&payload);
        drop(lease);
        result.map_err(|_| IssuerTokenError::Unavailable)
    })
    .await
    .map_err(|_| IssuerTokenError::Unavailable)?
}
