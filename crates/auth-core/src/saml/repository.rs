use super::SamlRegistration;
use crate::{Error, Result, Verifier};
use async_trait::async_trait;

pub struct SamlRequestAdmission<'a> {
    pub request_id: &'a str,
    pub relay: Verifier,
    pub browser: Verifier,
}

impl SamlRequestAdmission<'_> {
    /// The generated request-ID profile shared by use cases and storage ports.
    pub fn validate(&self) -> Result<()> {
        let id = self.request_id;
        if !(2..=128).contains(&id.len())
            || !id.starts_with('_')
            || !id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
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
