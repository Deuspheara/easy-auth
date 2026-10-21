use super::SamlMappedIdentity;
use crate::{
    Error, Result, SamlRegistration, VerifiedSamlAssertion, display_name::usable_display_name,
};

/// Trusted administrative opt-in for creating an owner. Never permits email
/// matching or a credential/lifecycle fallback. Existing ownership is separate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SamlJitPolicy {
    #[default]
    Deny,
    Allow,
}

/// Exact-registration policy for the initial persistent-NameID-only profile.
/// The verifier already requires exact issuer, SP audience and qualified subject.
/// Attributes, email, roles and presentation never select a local owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SamlIdentityPolicy {
    registration: SamlRegistration,
    jit: SamlJitPolicy,
}
impl SamlIdentityPolicy {
    pub fn new(registration: SamlRegistration) -> Self {
        Self {
            registration,
            jit: SamlJitPolicy::Deny,
        }
    }

    /// Trusted configuration only. Persistence must rotate registration revision
    /// and replace pins/policy atomically; this in-memory value grants nothing.
    #[must_use]
    pub fn with_jit(mut self, jit: SamlJitPolicy) -> Self {
        self.jit = jit;
        self
    }

    pub fn registration(&self) -> &SamlRegistration {
        &self.registration
    }
    pub fn jit(&self) -> SamlJitPolicy {
        self.jit
    }

    /// Consume actual signature evidence into a policy-bound proof. Final replay,
    /// identity/session ownership, current policy and DB caps remain mandatory.
    pub fn map(&self, assertion: VerifiedSamlAssertion) -> Result<SamlMappedIdentity> {
        if assertion.registration() != &self.registration {
            return Err(Error::Unauthorized);
        }
        let display_name = Some(assertion.subject())
            .filter(|s| usable_display_name(s))
            .map(str::to_owned);
        Ok(SamlMappedIdentity::new(
            self.clone(),
            assertion,
            display_name,
        ))
    }
}
