use crate::{Result, SamlRegistration, SamlRequestAdmission, SamlRequestTiming, Verifier};
use async_trait::async_trait;
use uuid::Uuid;

/// Trusted persistence correlation only; IDs are not authority or signature proof.
pub struct SamlDeletionBinding {
    pub user: Uuid,
    pub session: Uuid,
    pub identity: Uuid,
}
/// Backend-observed original cap and initiating source binding after consumption.
pub struct SamlDeletionRequestContext {
    pub binding: SamlDeletionBinding,
    pub timing: SamlRequestTiming,
}
#[async_trait]
pub trait SamlDeletionRequestRepository: Send + Sync {
    /// Require a current exact SAML source and active initiating session; commit
    /// deletion purpose and hash-only proofs with original request/session caps.
    async fn save_saml_deletion_request(
        &self,
        registration: &SamlRegistration,
        current: Verifier,
        admission: SamlRequestAdmission<'_>,
    ) -> Result<i64>;
    async fn cancel_saml_deletion_request(
        &self,
        registration: &SamlRegistration,
        current: Verifier,
        admission: SamlRequestAdmission<'_>,
    ) -> Result<()>;
    /// Consume only the exact deletion purpose and initiating source/owner/session.
    /// Signature verification and destructive authority are separate later steps.
    async fn take_saml_deletion_request(
        &self,
        registration: &SamlRegistration,
        current: Verifier,
        admission: SamlRequestAdmission<'_>,
    ) -> Result<SamlDeletionRequestContext>;
}
