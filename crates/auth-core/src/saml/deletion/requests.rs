use super::super::request_generation::RequestDraft;
use super::{SamlDeletionRequestRepository, SamlPreparedDeletion};
use crate::{
    Error, Result, SamlBrowserProof, SamlPreparedResponse, SamlRegistration, SamlRequestAdmission,
    SamlStart, Secret,
};
use std::sync::Arc;

pub struct SamlDeletionRequests {
    registration: SamlRegistration,
    repository: Arc<dyn SamlDeletionRequestRepository>,
}
impl SamlDeletionRequests {
    pub fn new(
        registration: SamlRegistration,
        repository: Arc<dyn SamlDeletionRequestRepository>,
    ) -> Self {
        Self {
            registration,
            repository,
        }
    }
    pub fn registration(&self) -> &SamlRegistration {
        &self.registration
    }
    /// Request real provider reauthentication; ForceAuthn is intent, not freshness
    /// evidence. Preparation cannot authenticate or erase a local account.
    pub async fn start(&self, current: &Secret) -> Result<SamlStart> {
        let request = RequestDraft::new(&self.registration, Some(true))?;
        let cap = self
            .repository
            .save_saml_deletion_request(&self.registration, current.verifier(), request.admission())
            .await?;
        Ok(request.committed(cap))
    }
    pub async fn cancel(
        &self,
        current: &Secret,
        request_id: &str,
        relay: &Secret,
        browser: &SamlBrowserProof,
    ) -> Result<()> {
        let admission = admission(request_id, relay, browser)?;
        self.repository
            .cancel_saml_deletion_request(&self.registration, current.verifier(), admission)
            .await
    }
    pub async fn prepare_response(
        &self,
        current: &Secret,
        request_id: &str,
        relay: &Secret,
        browser: &SamlBrowserProof,
    ) -> Result<SamlPreparedDeletion> {
        let admission = admission(request_id, relay, browser)?;
        let context = self
            .repository
            .take_saml_deletion_request(&self.registration, current.verifier(), admission)
            .await?;
        if context.binding.user.is_nil()
            || context.binding.session.is_nil()
            || context.binding.identity.is_nil()
            || context.timing.observed_at_us <= 0
            || context.timing.observed_at_us >= context.timing.expires_at_us
        {
            return Err(Error::Unavailable);
        }
        Ok(SamlPreparedDeletion {
            binding: context.binding,
            response: SamlPreparedResponse {
                registration: self.registration.clone(),
                request_id: request_id.to_owned(),
                timing: context.timing,
            },
        })
    }
}
fn admission<'a>(
    request_id: &'a str,
    relay: &Secret,
    browser: &SamlBrowserProof,
) -> Result<SamlRequestAdmission<'a>> {
    let admission = SamlRequestAdmission {
        request_id,
        relay: relay.verifier(),
        browser: browser.0.verifier(),
    };
    admission.validate().map_err(|_| Error::Unauthorized)?;
    Ok(admission)
}
