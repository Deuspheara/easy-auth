use super::{AppleGrantEnvelope, AppleGrantKey, keys::KeySet, protection};
use crate::{Error, Result};
use std::sync::Arc;
use tokio::sync::Semaphore;

const MAX_STORAGE_WORKERS: usize = 4;
/// Explicit protected key selection for Apple grant storage. Rewrapping cannot
/// produce an identity/session or claim that remote revocation was performed.
pub struct AppleGrantVault {
    pub(super) keys: Arc<KeySet>,
    workers: Arc<Semaphore>,
}
impl AppleGrantVault {
    pub fn new(current: AppleGrantKey, retained: Vec<AppleGrantKey>) -> Result<Self> {
        Ok(Self {
            keys: Arc::new(KeySet::new(current, retained)?),
            workers: Arc::new(Semaphore::new(MAX_STORAGE_WORKERS)),
        })
    }
    pub async fn rewrap(&self, envelope: &AppleGrantEnvelope) -> Result<AppleGrantEnvelope> {
        let envelope = envelope.clone();
        self.blocking(move |keys| {
            let payload = protection::open(keys, &envelope)?;
            protection::seal(keys, envelope.binding, payload)
        })
        .await
    }
    async fn blocking<T: Send + 'static>(
        &self,
        action: impl FnOnce(&KeySet) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let lease = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::RateLimited)?;
        let keys = self.keys.clone();
        tokio::task::spawn_blocking(move || {
            // Cancelling the async waiter does not release capacity or key/input
            // ownership while native work is still executing.
            let _lease = lease;
            action(&keys)
        })
        .await
        .map_err(|_| Error::Unavailable)?
    }
}

#[cfg(test)]
#[path = "tests/workers.rs"]
mod worker_tests;
