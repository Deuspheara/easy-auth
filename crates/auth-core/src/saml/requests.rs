use super::{
    SamlBrowserProof, SamlPreparedResponse, SamlRegistration, SamlRequestAdmission,
    SamlRequestRepository, SamlStart,
};
use crate::{Error, Result, Secret};
use std::sync::Arc;
use zeroize::Zeroizing;

pub const SAML_REQUEST_LIFETIME_SECONDS: i64 = 300;
/// Pending storage bound, not an HTTP attempt-rate limiter or DoS assurance.
pub const MAX_SAML_PENDING_PER_CONNECTION: i64 = 128;

pub struct SamlTransactions {
    registration: SamlRegistration,
    repository: Arc<dyn SamlRequestRepository>,
}

impl SamlTransactions {
    pub fn new(registration: SamlRegistration, repository: Arc<dyn SamlRequestRepository>) -> Self {
        Self {
            registration,
            repository,
        }
    }

    pub async fn start(&self) -> Result<SamlStart> {
        let relay_state = Secret::generate()?;
        let browser = SamlBrowserProof(Secret::generate()?);
        let request = self.registration.login_request(relay_state.expose())?;
        let authorization_url = Zeroizing::new(request.context);
        if request.id.is_empty()
            || request.id.len() > 128
            || request.entity_endpoint != self.registration.sso()
        {
            return Err(Error::Unavailable);
        }
        let expires_at_ms = self
            .repository
            .save_saml_request(
                &self.registration,
                SamlRequestAdmission {
                    request_id: &request.id,
                    relay: relay_state.verifier(),
                    browser: browser.0.verifier(),
                },
            )
            .await?;
        Ok(SamlStart {
            request_id: request.id,
            authorization_url,
            relay_state,
            browser,
            expires_at_ms,
        })
    }

    pub async fn cancel(
        &self,
        request_id: &str,
        relay: &Secret,
        browser: &SamlBrowserProof,
    ) -> Result<()> {
        if request_id.is_empty()
            || request_id.len() > 128
            || request_id.chars().any(char::is_control)
        {
            return Err(Error::Unauthorized);
        }
        self.repository
            .cancel_saml_request(
                &self.registration,
                SamlRequestAdmission {
                    request_id,
                    relay: relay.verifier(),
                    browser: browser.0.verifier(),
                },
            )
            .await
    }

    /// Consume a bound request before response verification. Success means only
    /// request correlation was established; it cannot authenticate a subject.
    pub async fn prepare_response(
        &self,
        request_id: &str,
        relay: &Secret,
        browser: &SamlBrowserProof,
    ) -> Result<SamlPreparedResponse> {
        let admission = SamlRequestAdmission {
            request_id,
            relay: relay.verifier(),
            browser: browser.0.verifier(),
        };
        admission.validate().map_err(|_| Error::Unauthorized)?;
        let timing = self
            .repository
            .take_saml_request(&self.registration, admission)
            .await?;
        if timing.observed_at_us <= 0 || timing.observed_at_us >= timing.expires_at_us {
            return Err(Error::Unavailable);
        }
        Ok(SamlPreparedResponse {
            registration: self.registration.clone(),
            request_id: request_id.to_owned(),
            timing,
        })
    }
}
