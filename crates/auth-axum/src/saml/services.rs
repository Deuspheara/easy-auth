use super::deletion::SamlAccountDeletionWebServices;
use auth_core::{
    Error, Result, SamlIdentityPolicy, SamlIdentityRepository, SamlRequestRepository,
    SamlResponseVerifier, SamlSignIn, SamlTransactions, SamlVerificationRepository,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct SamlWebServices {
    pub(super) policy: SamlIdentityPolicy,
    pub(super) transactions: Arc<SamlTransactions>,
    pub(super) verifier: Arc<SamlResponseVerifier>,
    pub(super) sign_in: Arc<SamlSignIn>,
    pub(super) deletion: Option<Arc<SamlAccountDeletionWebServices>>,
}
impl SamlWebServices {
    /// Trusted exact policy; component source snapshots cannot drift apart.
    pub fn new(
        policy: SamlIdentityPolicy,
        requests: Arc<dyn SamlRequestRepository>,
        verification: Arc<dyn SamlVerificationRepository>,
        identities: Arc<dyn SamlIdentityRepository>,
    ) -> Result<Self> {
        let reg = policy.registration().clone();
        Ok(Self {
            policy,
            transactions: Arc::new(SamlTransactions::new(reg.clone(), requests)),
            verifier: Arc::new(SamlResponseVerifier::new(reg, verification)?),
            sign_in: Arc::new(SamlSignIn::new(identities)),
            deletion: None,
        })
    }
    /// Add the explicit destructive operation for the identical full policy.
    /// The existing constructor and ordinary server expose no deletion routes.
    pub fn with_account_deletion(
        mut self,
        mut services: SamlAccountDeletionWebServices,
    ) -> Result<Self> {
        if self.deletion.is_some() || services.policy != self.policy {
            return Err(Error::InvalidInput);
        }
        // Both entry points share native admission; their repositories, proof
        // types and operation-specific authority checks remain separate.
        services.share_verification_capacity(&self.verifier)?;
        self.deletion = Some(Arc::new(services));
        Ok(self)
    }
}
