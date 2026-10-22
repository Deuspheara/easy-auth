use auth_core::{
    Result, SamlAccountDeletion, SamlAccountDeletionRepository, SamlDeletionRequestRepository,
    SamlDeletionRequests, SamlDeletionVerifier, SamlIdentityPolicy, SamlVerificationRepository,
};
use std::sync::Arc;

/// Explicit engineering-only deletion composition for one exact persisted policy.
/// Adding these services never activates normal server SAML or changes its gate.
pub struct SamlAccountDeletionWebServices {
    pub(in crate::saml) policy: SamlIdentityPolicy,
    pub(super) requests: SamlDeletionRequests,
    pub(super) verifier: SamlDeletionVerifier,
    pub(super) deletion: SamlAccountDeletion,
}
impl SamlAccountDeletionWebServices {
    pub fn new(
        policy: SamlIdentityPolicy,
        requests: Arc<dyn SamlDeletionRequestRepository>,
        verification: Arc<dyn SamlVerificationRepository>,
        deletion: Arc<dyn SamlAccountDeletionRepository>,
    ) -> Result<Self> {
        Ok(Self {
            requests: SamlDeletionRequests::new(policy.registration().clone(), requests),
            verifier: SamlDeletionVerifier::new(policy.clone(), verification)?,
            deletion: SamlAccountDeletion::new(deletion),
            policy,
        })
    }
}
