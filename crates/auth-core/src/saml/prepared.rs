use super::SamlRegistration;
use std::fmt;

/// Trusted storage timing only. This is not signature evidence or an identity
/// proof. Adapters return the original persisted cap and observed database time.
pub struct SamlRequestTiming {
    pub expires_at_us: i64,
    pub observed_at_us: i64,
}

/// A consumed, browser-bound AuthnRequest awaiting protocol verification.
///
/// Pass this by value to the eventual verifier. It carries no verified Assertion,
/// local owner or session authority. Consumption does not establish successful
/// authentication or replace the separate response/Assertion replay ledger.
pub struct SamlPreparedResponse {
    pub(super) registration: SamlRegistration,
    pub(super) request_id: String,
    pub(super) timing: SamlRequestTiming,
}

impl SamlPreparedResponse {
    pub fn registration(&self) -> &SamlRegistration {
        &self.registration
    }
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    /// Original database deadline, never extended by preparation or verification.
    pub fn expires_at_us(&self) -> i64 {
        self.timing.expires_at_us
    }
    /// Database observation for initial protocol time checks. Final completion
    /// must recheck current DB time against all original and signed deadlines.
    pub fn observed_at_us(&self) -> i64 {
        self.timing.observed_at_us
    }
}

impl fmt::Debug for SamlPreparedResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SamlPreparedResponse([REDACTED; not authenticated])")
    }
}
