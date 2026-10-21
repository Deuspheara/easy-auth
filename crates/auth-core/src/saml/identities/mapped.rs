use super::SamlIdentityPolicy;
use crate::VerifiedSamlAssertion;
use std::fmt;
use zeroize::Zeroizing;

/// Consumed real signature proof and exact policy; no local authentication grant,
/// durable replay admission or public constructor/Clone/serialization contract.
#[must_use]
pub struct SamlMappedIdentity {
    policy: SamlIdentityPolicy,
    assertion: VerifiedSamlAssertion,
    display_name: Option<Zeroizing<String>>,
}
impl SamlMappedIdentity {
    pub(super) fn new(
        policy: SamlIdentityPolicy,
        assertion: VerifiedSamlAssertion,
        display_name: Option<String>,
    ) -> Self {
        Self {
            policy,
            assertion,
            display_name: display_name.map(Zeroizing::new),
        }
    }
    pub fn policy(&self) -> &SamlIdentityPolicy {
        &self.policy
    }
    pub fn assertion(&self) -> &VerifiedSamlAssertion {
        &self.assertion
    }
    /// Optional initial presentation only. Missing/unusable metadata must block
    /// JIT, not the eventual resolution of an already bound existing subject.
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_ref().map(|s| s.as_str())
    }
}
impl fmt::Debug for SamlMappedIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SamlMappedIdentity([REDACTED; not committed])")
    }
}
