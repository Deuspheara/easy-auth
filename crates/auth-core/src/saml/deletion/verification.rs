use super::{SamlPreparedDeletion, SamlVerifiedDeletion};
use crate::{
    Error, Result, SamlIdentityPolicy, SamlPostResponse, SamlRegistration, SamlResponseVerifier,
    SamlVerificationRepository,
};
use std::sync::Arc;

/// The existing five-minute sensitive-action policy, applied to signed provider
/// authentication time; ForceAuthn and local request/session time are not proof.
pub const MAX_SAML_DELETION_AUTH_AGE_SECONDS: u64 = 300;
const AUTHENTICATION_FRESHNESS_US: i64 = (MAX_SAML_DELETION_AUTH_AGE_SECONDS * 1_000_000) as i64;

pub struct SamlDeletionVerifier {
    policy: SamlIdentityPolicy,
    verifier: SamlResponseVerifier,
}

impl SamlDeletionVerifier {
    pub fn new(
        policy: SamlIdentityPolicy,
        repository: Arc<dyn SamlVerificationRepository>,
    ) -> Result<Self> {
        let verifier = SamlResponseVerifier::new(policy.registration().clone(), repository)?;
        Ok(Self { policy, verifier })
    }
    /// Share admission with sign-in for the identical registration, while
    /// retaining this verifier's repository and deletion-specific proof policy.
    /// Join before exposing the service; an occupied previous budget rejects.
    /// This bounds one composition, not every independently constructed service.
    pub fn share_verification_capacity(&mut self, sign_in: &SamlResponseVerifier) -> Result<()> {
        self.verifier.share_capacity_with(sign_in)
    }
    pub fn policy(&self) -> &SamlIdentityPolicy {
        &self.policy
    }
    pub fn registration(&self) -> &SamlRegistration {
        self.policy.registration()
    }
    /// Verify the real response through the unchanged concrete adapter. This
    /// consumes only the opaque deletion preparation and exposes no sign-in proof.
    pub async fn verify(
        &self,
        prepared: SamlPreparedDeletion,
        input: SamlPostResponse,
    ) -> Result<SamlVerifiedDeletion> {
        let assertion = self.verifier.verify(prepared.response, input).await?;
        let fresh_until_us = assertion
            .authenticated_at_us()
            .checked_add(AUTHENTICATION_FRESHNESS_US)
            .ok_or(Error::Unauthorized)?;
        let mapped = self.policy.map(assertion)?;
        Ok(SamlVerifiedDeletion {
            mapped,
            binding: prepared.binding,
            fresh_until_us,
        })
    }
}
