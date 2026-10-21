use super::SamlRegistration;
use crate::{Result, Verifier};
use async_trait::async_trait;

pub struct SamlRequestAdmission<'a> {
    pub request_id: &'a str,
    pub relay: Verifier,
    pub browser: Verifier,
}

#[async_trait]
pub trait SamlRequestRepository: Send + Sync {
    /// Commit original database expiry and hash-only proofs under current exact
    /// enabled registration. Returns the original expiry in Unix milliseconds.
    /// It creates no identity/session and must enforce pending-storage bounds.
    async fn save_saml_request(
        &self,
        registration: &SamlRegistration,
        admission: SamlRequestAdmission<'_>,
    ) -> Result<i64>;

    /// One-use cancellation, bound to realm/connection/client/revision and both
    /// proofs. Wrong proof/current authority must leave pending state untouched.
    async fn cancel_saml_request(
        &self,
        registration: &SamlRegistration,
        admission: SamlRequestAdmission<'_>,
    ) -> Result<()>;
}
