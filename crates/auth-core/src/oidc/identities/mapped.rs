use super::OidcIdentityPolicy;
use crate::VerifiedOidcIdentity;
use std::fmt;

/// Consumed signed identity plus exact trusted mapping policy. No constructor,
/// Clone or Serialize; this is not a local authentication or provisioning grant.
#[must_use]
pub struct OidcMappedIdentity {
    policy: OidcIdentityPolicy,
    identity: VerifiedOidcIdentity,
    display_name: String,
}

impl OidcMappedIdentity {
    pub(super) fn new(
        policy: OidcIdentityPolicy,
        identity: VerifiedOidcIdentity,
        display_name: String,
    ) -> Self {
        Self {
            policy,
            identity,
            display_name,
        }
    }
    pub fn policy(&self) -> &OidcIdentityPolicy {
        &self.policy
    }
    pub fn identity(&self) -> &VerifiedOidcIdentity {
        &self.identity
    }
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

impl fmt::Debug for OidcMappedIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcMappedIdentity([REDACTED])")
    }
}
