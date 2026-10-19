use super::MAX_CREDENTIAL_ID_BYTES;
use crate::{Error, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fmt;
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

const MAX_STORED_CREDENTIAL_BYTES: usize = 64 * 1024;

/// A credential loaded with its trusted realm/RP/owner metadata. Never decode a
/// client-provided object as a stored credential.
pub struct StoredPasskey {
    pub(super) realm: Uuid,
    pub(super) owner: Uuid,
    pub(super) rp_id: String,
    pub(super) credential: Passkey,
    pub(super) backup_eligible: bool,
    pub(super) encoded: Vec<u8>,
}

// Projection of the pinned library's documented persistence serialization, not
// assertion parsing. Keep this version-bound and covered by real registrations.
#[derive(Deserialize)]
struct PersistedPasskey {
    cred: CredentialProperties,
}

#[derive(Deserialize)]
struct CredentialProperties {
    backup_eligible: bool,
}

impl StoredPasskey {
    pub fn decode_from_database(
        realm: Uuid,
        owner: Uuid,
        rp_id: &str,
        credential_id: &[u8],
        encoded: &[u8],
    ) -> Result<Self> {
        if realm.is_nil()
            || owner.is_nil()
            || rp_id.is_empty()
            || credential_id.is_empty()
            || credential_id.len() > MAX_CREDENTIAL_ID_BYTES
            || encoded.len() > MAX_STORED_CREDENTIAL_BYTES
        {
            return Err(Error::Unavailable);
        }
        let credential: Passkey =
            serde_json::from_slice(encoded).map_err(|_| Error::Unavailable)?;
        let properties: PersistedPasskey =
            serde_json::from_slice(encoded).map_err(|_| Error::Unavailable)?;
        if credential.cred_id().as_slice() != credential_id {
            return Err(Error::Unavailable);
        }
        Ok(Self {
            realm,
            owner,
            rp_id: rp_id.to_owned(),
            credential,
            backup_eligible: properties.cred.backup_eligible,
            encoded: encoded.to_vec(),
        })
    }

    pub(super) fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.encoded).into()
    }
}

impl fmt::Debug for StoredPasskey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoredPasskey([REDACTED])")
    }
}

/// Verified proof, not a session. Commit only while the exact original credential
/// and private ceremony still match under database locks; consume and update atomically.
pub struct VerifiedPasskeyAuthentication {
    pub(super) original: StoredPasskey,
    pub(super) updated: Vec<u8>,
}

impl VerifiedPasskeyAuthentication {
    pub fn realm(&self) -> Uuid {
        self.original.realm
    }

    pub fn user_id(&self) -> Uuid {
        self.original.owner
    }

    pub fn rp_id(&self) -> &str {
        &self.original.rp_id
    }

    pub fn credential_id(&self) -> &[u8] {
        self.original.credential.cred_id().as_slice()
    }

    pub fn expected_credential_for_database(&self) -> &[u8] {
        &self.original.encoded
    }

    pub fn updated_credential_for_database(&self) -> &[u8] {
        &self.updated
    }
}

impl fmt::Debug for VerifiedPasskeyAuthentication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedPasskeyAuthentication([REDACTED])")
    }
}
