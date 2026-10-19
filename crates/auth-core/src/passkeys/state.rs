use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use webauthn_rs::prelude::{Passkey, PasskeyRegistration};

const STATE_VERSION: u8 = 1;
const MAX_REGISTRATION_STATE_BYTES: usize = 32 * 1024;

/// Private server-side state. Never place its database encoding in a cookie or response.
/// This type deliberately has no Serialize implementation.
pub struct PrivatePasskeyRegistration {
    pub(super) origin: String,
    pub(super) state: PasskeyRegistration,
}

#[derive(Serialize, Deserialize)]
struct StoredRegistration {
    version: u8,
    origin: String,
    state: PasskeyRegistration,
}

impl PrivatePasskeyRegistration {
    /// Encode for trusted server persistence only. The adapter owns expiry and atomic consumption.
    pub fn encode_for_database(&self) -> Result<Vec<u8>> {
        let encoded = serde_json::to_vec(&StoredRegistration {
            version: STATE_VERSION,
            origin: self.origin.clone(),
            state: self.state.clone(),
        })
        .map_err(|_| Error::Unavailable)?;
        if encoded.len() > MAX_REGISTRATION_STATE_BYTES {
            return Err(Error::Unavailable);
        }
        Ok(encoded)
    }

    /// Decode only a row loaded from trusted server persistence, never client input.
    pub fn decode_from_database(encoded: &[u8]) -> Result<Self> {
        if encoded.len() > MAX_REGISTRATION_STATE_BYTES {
            return Err(Error::Unavailable);
        }
        let stored: StoredRegistration =
            serde_json::from_slice(encoded).map_err(|_| Error::Unavailable)?;
        if stored.version != STATE_VERSION {
            return Err(Error::Unavailable);
        }
        Ok(Self {
            origin: stored.origin,
            state: stored.state,
        })
    }
}

impl fmt::Debug for PrivatePasskeyRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivatePasskeyRegistration([REDACTED])")
    }
}

/// A credential verified by the high-level library. It still needs an atomic ownership insert.
pub struct VerifiedPasskey {
    pub(super) rp_id: String,
    pub(super) credential: Passkey,
}

impl VerifiedPasskey {
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    pub fn credential_id(&self) -> &[u8] {
        self.credential.cred_id().as_slice()
    }

    /// Preserve the library object, including counter/backup state, in server storage.
    pub fn encode_for_database(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&self.credential).map_err(|_| Error::Unavailable)
    }
}

impl fmt::Debug for VerifiedPasskey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedPasskey([REDACTED])")
    }
}
