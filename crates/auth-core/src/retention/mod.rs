//! Trusted operator maintenance; no browser or application authorization surface.
mod category;
mod policy;
#[cfg(test)]
mod tests;

use crate::{Error, Result};
use async_trait::async_trait;
use uuid::Uuid;

pub use category::RetentionCategory;
pub use policy::{RetentionHorizon, RetentionPolicy};

pub const RETENTION_BATCH_LIMIT: u64 = 64;

/// Committed effects only. Ciphertext expiry is never confirmed remote revocation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RetentionBatch {
    pub deleted: u64,
    pub expired_ciphertexts: u64,
    pub exhausted_leases: u64,
}

#[derive(Debug)]
pub struct RetentionStep {
    pub category: RetentionCategory,
    pub effects: RetentionBatch,
}

#[derive(Debug)]
pub struct RetentionReport {
    pub steps: Vec<RetentionStep>,
}

#[async_trait]
pub trait RetentionRepository: Send + Sync {
    /// One independently committed bounded category. Use fresh database time after
    /// candidate locking; preserve current references and prohibit parent cascades.
    async fn retain_batch(
        &self,
        realm: Uuid,
        category: RetentionCategory,
        policy: RetentionPolicy,
    ) -> Result<RetentionBatch>;
}

/// Run one finite pass, never an unbounded drain. Earlier batches may have committed
/// if a later operation fails. Locked/referenced rows require subsequent passes;
/// zero counts do not establish that a realm has no backlog.
pub async fn run_retention(
    repository: &dyn RetentionRepository,
    realm: Uuid,
    policy: RetentionPolicy,
) -> Result<RetentionReport> {
    if realm.is_nil() {
        return Err(Error::InvalidInput);
    }
    let mut steps = Vec::with_capacity(RetentionCategory::ALL.len());
    for category in RetentionCategory::ALL {
        let effects = repository.retain_batch(realm, category, policy).await?;
        steps.push(RetentionStep { category, effects });
    }
    Ok(RetentionReport { steps })
}
