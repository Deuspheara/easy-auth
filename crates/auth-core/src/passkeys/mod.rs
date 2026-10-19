mod authentication;
mod authentication_repository;
mod authentication_state;
mod client_context;
mod configuration;
mod credential;
mod enrollment;
mod logging;
mod registration;
mod repository;
mod sign_in;
mod state;
#[cfg(test)]
mod tests;

pub use authentication_repository::{
    PasskeyAuthenticationRepository, PasskeyAuthenticationRequest, PasskeyAuthenticationStart,
};
pub use authentication_state::PrivatePasskeyAuthentication;
pub use credential::{StoredPasskey, VerifiedPasskeyAuthentication};
pub use enrollment::{PasskeyEnrollment, PasskeyEnrollmentOptions};
pub use repository::{
    PasskeyEnrollmentContext, PasskeyEnrollmentRequest, PasskeyEnrollmentStart, PasskeyRepository,
};
pub use sign_in::{PasskeySignIn, PasskeySignInOptions};
pub use state::{PrivatePasskeyRegistration, VerifiedPasskey};
pub use webauthn_rs::prelude::{
    CreationChallengeResponse as PasskeyCreationOptions,
    PublicKeyCredential as PasskeyAuthenticationResponse,
    RegisterPublicKeyCredential as PasskeyRegistrationResponse,
    RequestChallengeResponse as PasskeyAuthenticationOptions,
};

use crate::{Error, Result};
use std::time::Duration;
use url::Url;
use webauthn_rs::prelude::{Webauthn, WebauthnBuilder};

const CEREMONY_TIMEOUT: Duration = Duration::from_secs(120);
pub const MAX_PASSKEYS_PER_ACCOUNT: usize = 10;
const MAX_CREDENTIAL_ID_BYTES: usize = 1024;

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

    pub fn origin(&self) -> &str {
        self.origin.as_str()
    }
}
