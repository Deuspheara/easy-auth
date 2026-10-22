use super::{attributes::SamlAttribute, replay::SamlReplayRecord};
use crate::SamlRegistration;
use std::fmt;
use zeroize::Zeroizing;

/// Signature-verified facts awaiting durable replay/current-source/identity/session
/// commit. This is deliberately NOT a local authentication grant. Only the concrete
/// verifier can construct it. It is consumed by value at a future commit boundary.
pub struct VerifiedSamlAssertion {
    pub(super) registration: SamlRegistration,
    pub(super) subject: Zeroizing<String>,
    pub(super) attributes: Vec<SamlAttribute>,
    pub(super) authn_at_us: i64,
    pub(super) expires_at_us: i64,
    pub(super) session_expires_at_us: i64,
    pub(super) certificate: [u8; 32],
    pub(super) replay: Vec<SamlReplayRecord>,
}
impl VerifiedSamlAssertion {
    pub fn registration(&self) -> &SamlRegistration {
        &self.registration
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    /// Ordered scalar records, retaining exact Name/NameFormat and value groups.
    /// Duplicate names are not merged. They grant no identity or authorization.
    pub fn attributes(&self) -> &[SamlAttribute] {
        &self.attributes
    }
    pub fn authenticated_at_us(&self) -> i64 {
        self.authn_at_us
    }
    pub fn expires_at_us(&self) -> i64 {
        self.expires_at_us
    }
    /// Upper bound for a future local session, from actual signed authn time,
    /// fixed 24h policy and any signed SessionNotOnOrAfter. Distinct from the
    /// short original-request/assertion admission cap. Grants no session alone.
    pub fn session_expires_at_us(&self) -> i64 {
        self.session_expires_at_us
    }
    pub fn certificate_fingerprint(&self) -> &[u8; 32] {
        &self.certificate
    }
    pub fn replay_reservations(&self) -> &[SamlReplayRecord] {
        &self.replay
    }
}
impl fmt::Debug for VerifiedSamlAssertion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedSamlAssertion([REDACTED; not committed])")
    }
}
