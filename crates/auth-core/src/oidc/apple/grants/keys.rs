use crate::{Error, Result};
use std::{collections::BTreeMap, fmt};
use uuid::Uuid;
use zeroize::Zeroizing;

const STORAGE_KEY_BYTES: usize = 32;
const MAX_STORAGE_KEYS: usize = 8;

/// Trusted operator input: cryptographically random32-byte storage key, distinct
/// from the Apple signing key. No default/generation/request/SQL loader is supplied.
pub struct AppleGrantKey {
    pub(super) id: Uuid,
    pub(super) bytes: Zeroizing<Vec<u8>>,
}
impl AppleGrantKey {
    pub fn new(id: Uuid, bytes: Vec<u8>) -> Result<Self> {
        let bytes = Zeroizing::new(bytes);
        if id.is_nil() || bytes.len() != STORAGE_KEY_BYTES || bytes.iter().all(|b| *b == 0) {
            return Err(Error::InvalidInput);
        }
        Ok(Self { id, bytes })
    }
}
impl fmt::Debug for AppleGrantKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppleGrantKey([REDACTED])")
    }
}
pub(super) struct KeySet {
    pub current: Uuid,
    keys: BTreeMap<Uuid, AppleGrantKey>,
}
impl KeySet {
    pub fn new(current: AppleGrantKey, retained: Vec<AppleGrantKey>) -> Result<Self> {
        if retained.len() >= MAX_STORAGE_KEYS {
            return Err(Error::InvalidInput);
        }
        let current_id = current.id;
        let mut keys = BTreeMap::new();
        keys.insert(current.id, current);
        for key in retained {
            if keys.insert(key.id, key).is_some() {
                return Err(Error::InvalidInput);
            }
        }
        Ok(Self {
            current: current_id,
            keys,
        })
    }
    pub fn key(&self, id: Uuid) -> Result<&AppleGrantKey> {
        // A missing protected key is an availability/configuration failure; never
        // try every key or silently replace it with the current writing key.
        self.keys.get(&id).ok_or(Error::Unavailable)
    }
}
