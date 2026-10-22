//! Process-wide admission for concrete native SAML verification.
use crate::{Error, Result};
use std::{
    sync::{Arc, LazyLock},
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

// Preserve the established two-operation budget across independently constructed
// services as well as within one sign-in/deletion composition.
const MAX_PROCESS_VERIFICATIONS: usize = 2;
static WORKERS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_PROCESS_VERIFICATIONS)));

pub(super) async fn acquire(wait: Duration) -> Result<OwnedSemaphorePermit> {
    // Normal operations from separate services may wait for one another. Their
    // own two-operation budgets still reject local overload immediately.
    tokio::time::timeout(wait, WORKERS.clone().acquire_owned())
        .await
        .map_err(|_| Error::RateLimited)?
        .map_err(|_| Error::Unavailable)
}
