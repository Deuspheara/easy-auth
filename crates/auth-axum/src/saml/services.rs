use auth_core::{
    Result, SamlIdentityPolicy, SamlIdentityRepository, SamlRequestRepository,
    SamlResponseVerifier, SamlSignIn, SamlTransactions, SamlVerificationRepository,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct SamlWebServices {
    pub(super) policy: SamlIdentityPolicy,
    pub(super) transactions: Arc<SamlTransactions>,
    pub(super) verifier: Arc<SamlResponseVerifier>,
    pub(super) sign_in: Arc<SamlSignIn>,
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
        })
    }
}
