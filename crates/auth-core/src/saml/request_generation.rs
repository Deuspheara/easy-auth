//! Shared private generation before a caller commits a specific request purpose.
use super::{SamlBrowserProof, SamlRegistration, SamlRequestAdmission, SamlStart};
use crate::{Error, Result, Secret};
use zeroize::Zeroizing;

pub(super) struct RequestDraft {
    request_id: String,
    authorization_url: Zeroizing<String>,
    relay: Secret,
    browser: SamlBrowserProof,
}
impl RequestDraft {
    pub fn new(reg: &SamlRegistration, force_authn: Option<bool>) -> Result<Self> {
        let relay = Secret::generate()?;
        let browser = SamlBrowserProof(Secret::generate()?);
        let request = reg.login_request(relay.expose(), force_authn)?;
        if request.id.is_empty() || request.id.len() > 128 || request.entity_endpoint != reg.sso() {
            return Err(Error::Unavailable);
        }
        Ok(Self {
            request_id: request.id,
            authorization_url: Zeroizing::new(request.context),
            relay,
            browser,
        })
    }
    pub fn admission(&self) -> SamlRequestAdmission<'_> {
        SamlRequestAdmission {
            request_id: &self.request_id,
            relay: self.relay.verifier(),
            browser: self.browser.0.verifier(),
        }
    }
    pub fn committed(self, expires_at_ms: i64) -> SamlStart {
        SamlStart {
            request_id: self.request_id,
            authorization_url: self.authorization_url,
            relay_state: self.relay,
            browser: self.browser,
            expires_at_ms,
        }
    }
}
