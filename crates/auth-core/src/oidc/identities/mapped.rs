use super::OidcIdentityPolicy;
use crate::VerifiedOidcIdentity;
use std::fmt;

/// Consumed signed identity plus exact trusted mapping policy. No constructor,
/// Clone or Serialize; this is not a local authentication or provisioning grant.
#[must_use]
pub struct OidcMappedIdentity {
    policy: OidcIdentityPolicy,
    identity: VerifiedOidcIdentity,
    display_name: Option<String>,
}

impl OidcMappedIdentity {
    pub(super) fn new(
        policy: OidcIdentityPolicy,
        identity: VerifiedOidcIdentity,
        display_name: Option<String>,
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
    /// Initial metadata candidate. Absence blocks creating a new local owner,
    /// not authentication of an already-bound subject with stored presentation.
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }
}

impl fmt::Debug for OidcMappedIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcMappedIdentity([REDACTED])")
    }
}
