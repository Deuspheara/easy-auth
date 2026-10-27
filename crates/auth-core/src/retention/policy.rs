use crate::{Error, Result};
use std::time::Duration;

// An input/resource bound, not a recommended legal or evidence retention period.
const MAX_RETENTION_SECONDS: u64 = 100 * 365 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionHorizon(Option<u32>);

impl RetentionHorizon {
    pub const fn keep() -> Self {
        Self(None)
    }

    /// Explicit whole-second operator horizon. No default deletion period exists.
    pub fn after(age: Duration) -> Result<Self> {
        if age.subsec_nanos() != 0 || !(1..=MAX_RETENTION_SECONDS).contains(&age.as_secs()) {
            return Err(Error::InvalidInput);
        }
        Ok(Self(Some(age.as_secs() as u32)))
    }

    pub const fn seconds(self) -> Option<u32> {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionPolicy {
    audit: RetentionHorizon,
    exhausted_notices: RetentionHorizon,
}

impl RetentionPolicy {
    pub const fn new(audit: RetentionHorizon, exhausted_notices: RetentionHorizon) -> Self {
        Self {
            audit,
            exhausted_notices,
        }
    }

    pub const fn audit(self) -> RetentionHorizon {
        self.audit
    }

    pub const fn exhausted_notices(self) -> RetentionHorizon {
        self.exhausted_notices
    }
}
