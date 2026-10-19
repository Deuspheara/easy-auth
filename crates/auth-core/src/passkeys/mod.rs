mod configuration;
mod enrollment;
mod logging;
mod repository;
mod state;
#[cfg(test)]
mod tests;

pub use enrollment::{PasskeyEnrollment, PasskeyEnrollmentOptions};
pub use repository::{
    PasskeyEnrollmentContext, PasskeyEnrollmentRequest, PasskeyEnrollmentStart, PasskeyRepository,
};
pub use state::{PrivatePasskeyRegistration, VerifiedPasskey};
pub use webauthn_rs::prelude::{
    CreationChallengeResponse as PasskeyCreationOptions,
    RegisterPublicKeyCredential as PasskeyRegistrationResponse,
};

use crate::{Error, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::time::Duration;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{Webauthn, WebauthnBuilder};

const CEREMONY_TIMEOUT: Duration = Duration::from_secs(120);
pub const MAX_PASSKEYS_PER_ACCOUNT: usize = 10;
const MAX_CREDENTIAL_ID_BYTES: usize = 1024;
const MAX_REGISTRATION_RESPONSE_BYTES: usize = 16 * 1024;

/// Protocol verification only. Repository use cases must separately enforce ownership,
/// fresh authentication, expiry, admission and atomic single-use state consumption.
pub struct PasskeyService {
    verifier: Webauthn,
    origin: Url,
    rp_id: String,
}

impl PasskeyService {
    /// Require one exact HTTPS origin; the RP ID is its hostname.
    pub fn new(origin: &str, relying_party_name: &str) -> Result<Self> {
        Self::configured(origin, relying_party_name, false)
    }

    /// Explicit localhost-only development policy, including the exact configured port.
    pub fn for_local_development(origin: &str, relying_party_name: &str) -> Result<Self> {
        Self::configured(origin, relying_party_name, true)
    }

    fn configured(origin: &str, relying_party_name: &str, development: bool) -> Result<Self> {
        let origin = configuration::origin(origin, development)?;
        configuration::display_name(relying_party_name)?;
        let rp_id = origin.domain().ok_or(Error::InvalidInput)?;
        let verifier = WebauthnBuilder::new(rp_id, &origin)
            .map_err(|_| Error::InvalidInput)?
            .rp_name(relying_party_name)
            .allow_subdomains(false)
            .allow_any_port(false)
            .timeout(CEREMONY_TIMEOUT)
            .build()
            .map_err(|_| Error::InvalidInput)?;
        let rp_id = rp_id.to_owned();
        Ok(Self {
            verifier,
            origin,
            rp_id,
        })
    }

    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    pub fn begin_registration(
        &self,
        owner: Uuid,
        account_name: &str,
        excluded_credentials: &[Vec<u8>],
    ) -> Result<(PasskeyCreationOptions, PrivatePasskeyRegistration)> {
        configuration::display_name(account_name)?;
        if owner.is_nil()
            || excluded_credentials.len() >= MAX_PASSKEYS_PER_ACCOUNT
            || excluded_credentials
                .iter()
                .any(|id| id.is_empty() || id.len() > MAX_CREDENTIAL_ID_BYTES)
        {
            return Err(Error::InvalidInput);
        }
        let excluded = excluded_credentials
            .iter()
            .cloned()
            .map(Into::into)
            .collect();
        let (options, state) = logging::without_payload_events(|| {
            self.verifier.start_passkey_registration(
                owner,
                account_name,
                account_name,
                Some(excluded),
            )
        })
        .map_err(|_| Error::Unavailable)?;
        Ok((
            options,
            PrivatePasskeyRegistration {
                origin: self.origin.as_str().to_owned(),
                state,
            },
        ))
    }

    /// This consumes only the in-memory value. Database consumption is a separate transaction.
    pub fn verify_registration(
        &self,
        response: &PasskeyRegistrationResponse,
        state: PrivatePasskeyRegistration,
    ) -> Result<VerifiedPasskey> {
        if state.origin != self.origin.as_str() || !bounded_response(response) {
            return Err(Error::Unauthorized);
        }
        let credential = logging::without_payload_events(|| {
            self.verifier
                .finish_passkey_registration(response, &state.state)
        })
        .map_err(|_| Error::Unauthorized)?;
        if credential.cred_id().is_empty() || credential.cred_id().len() > MAX_CREDENTIAL_ID_BYTES {
            return Err(Error::Unauthorized);
        }
        // The verifier takes the credential ID from attested data. Reject contradictory
        // public envelope identifiers rather than letting later adapters interpret them.
        if response.raw_id.as_slice() != credential.cred_id().as_slice()
            || response.id != URL_SAFE_NO_PAD.encode(credential.cred_id().as_slice())
        {
            return Err(Error::Unauthorized);
        }
        Ok(VerifiedPasskey {
            rp_id: self.rp_id.clone(),
            credential,
        })
    }
}

fn bounded_response(response: &PasskeyRegistrationResponse) -> bool {
    let bytes = response
        .id
        .len()
        .saturating_add(response.raw_id.len())
        .saturating_add(response.response.attestation_object.len())
        .saturating_add(response.response.client_data_json.len());
    response.type_ == "public-key" && bytes <= MAX_REGISTRATION_RESPONSE_BYTES
}
