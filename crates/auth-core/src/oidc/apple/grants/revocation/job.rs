use super::super::AppleGrantEnvelope;
use crate::{Error, Result};
use std::fmt;
use uuid::Uuid;

/// Protected repository lease, not an identity/consent proof or a public API DTO.
#[derive(Clone)]
pub struct AppleGrantRevocationJob {
    envelope: AppleGrantEnvelope,
    lease: Uuid,
    version: i64,
    claimed_us: i64,
    until_us: i64,
}
impl AppleGrantRevocationJob {
    pub fn restore(
        envelope: AppleGrantEnvelope,
        lease: Uuid,
        version: i64,
        claimed_us: i64,
        until_us: i64,
    ) -> Result<Self> {
        if lease.is_nil() || version <= 0 || claimed_us < 0 || until_us <= claimed_us {
            return Err(Error::Unavailable);
        }
        Ok(Self {
            envelope,
            lease,
            version,
            claimed_us,
            until_us,
        })
    }
    pub fn envelope(&self) -> &AppleGrantEnvelope {
        &self.envelope
    }
    pub fn lease(&self) -> Uuid {
        self.lease
    }
    pub fn version(&self) -> i64 {
        self.version
    }
    pub fn claimed_us(&self) -> i64 {
        self.claimed_us
    }
    pub fn until_us(&self) -> i64 {
        self.until_us
    }
}
impl fmt::Debug for AppleGrantRevocationJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppleGrantRevocationJob([REDACTED])")
    }
}
/// Created only after a verified protected revocation response. Consuming it does
/// not bypass the repository's current lease/version/source/final-clock checks.
pub struct AppleRevocationConfirmation {
    pub(super) job: AppleGrantRevocationJob,
}
impl AppleRevocationConfirmation {
    pub fn job(&self) -> &AppleGrantRevocationJob {
        &self.job
    }
}
