use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;
use webauthn_rs::prelude::{DiscoverableAuthentication, PasskeyAuthentication};

const STATE_VERSION: u8 = 1;
const MAX_AUTHENTICATION_STATE_BYTES: usize = 128 * 1024;

/// Private server persistence only. The adapter must enforce browser binding, expiry,
/// purpose and atomic consumption. This deliberately does not implement Serialize.
pub struct PrivatePasskeyAuthentication {
    pub(super) realm: Uuid,
    pub(super) origin: String,
    pub(super) ceremony: AuthenticationCeremony,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum AuthenticationCeremony {
    AccountBound {
        owner: Uuid,
        credentials: Vec<CredentialSnapshot>,
        state: PasskeyAuthentication,
    },
    Discoverable {
        state: DiscoverableAuthentication,
    },
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct CredentialSnapshot {
    pub id: Vec<u8>,
    pub digest: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct StoredAuthentication {
    version: u8,
    realm: Uuid,
    origin: String,
    ceremony: AuthenticationCeremony,
}

impl PrivatePasskeyAuthentication {
    pub fn realm(&self) -> Uuid {
        self.realm
    }

    /// Encode for trusted database storage, never a response or cookie.
    pub fn encode_for_database(&self) -> Result<Vec<u8>> {
        let encoded = serde_json::to_vec(&StoredAuthentication {
            version: STATE_VERSION,
            realm: self.realm,
            origin: self.origin.clone(),
            ceremony: self.ceremony.clone(),
        })
        .map_err(|_| Error::Unavailable)?;
        if encoded.len() > MAX_AUTHENTICATION_STATE_BYTES {
            return Err(Error::Unavailable);
        }
        Ok(encoded)
    }

    /// Decode only an application-owned row, never client input.
    pub fn decode_from_database(encoded: &[u8]) -> Result<Self> {
        if encoded.len() > MAX_AUTHENTICATION_STATE_BYTES {
            return Err(Error::Unavailable);
        }
        let stored: StoredAuthentication =
            serde_json::from_slice(encoded).map_err(|_| Error::Unavailable)?;
        if stored.version != STATE_VERSION || stored.realm.is_nil() {
            return Err(Error::Unavailable);
        }
        Ok(Self {
            realm: stored.realm,
            origin: stored.origin,
            ceremony: stored.ceremony,
        })
    }
}

impl fmt::Debug for PrivatePasskeyAuthentication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivatePasskeyAuthentication([REDACTED])")
    }
}
