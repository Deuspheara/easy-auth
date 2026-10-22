use super::SamlDeletionBinding;
use crate::{Error, Result, SamlIdentityPolicy, SamlMappedIdentity, VerifiedSamlAssertion};
use std::fmt;

/// Real signature evidence bound to consumed deletion purpose. Not an erasure
/// grant: current ownership, freshness, replay and final caps still require commit.
#[must_use]
pub struct SamlVerifiedDeletion {
    pub(super) mapped: SamlMappedIdentity,
    pub(super) binding: SamlDeletionBinding,
    pub(super) fresh_until_us: i64,
}

impl SamlVerifiedDeletion {
    pub fn policy(&self) -> &SamlIdentityPolicy {
        self.mapped.policy()
    }
    pub fn assertion(&self) -> &VerifiedSamlAssertion {
        self.mapped.assertion()
    }
    pub fn binding(&self) -> &SamlDeletionBinding {
        &self.binding
    }
    /// Upper bound derived only from actual signed AuthnInstant. The database
    /// must reject a future instant and recheck this cap after all final writes.
    pub fn fresh_until_us(&self) -> i64 {
        self.fresh_until_us
    }
    /// Apply signed authentication freshness to the adapter's trusted database
    /// clock. This borrowed policy check grants nothing and replaces neither
    /// current-owner validation nor the final post-write deadline check.
    pub fn validate_authentication_at(&self, observed_at_us: i64) -> Result<()> {
        if observed_at_us < self.assertion().authenticated_at_us()
            || observed_at_us >= self.fresh_until_us
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}

impl fmt::Debug for SamlVerifiedDeletion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SamlVerifiedDeletion([REDACTED; not committed])")
    }
}
