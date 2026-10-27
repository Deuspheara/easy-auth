use super::AppleGrantBinding;
use crate::{Error, Result};
use std::fmt;
use uuid::Uuid;

pub(super) const MAX_ENVELOPE_BYTES: usize = 64 * 1024;

/// Protected storage material only; never a provider identity/local-session proof.
/// Restore only from protected storage, not a browser or token-upload endpoint.
#[derive(Clone)]
pub struct AppleGrantEnvelope {
    pub(super) binding: AppleGrantBinding,
    pub(super) key: Uuid,
    pub(super) ciphertext: String,
}
impl AppleGrantEnvelope {
    pub fn restore(binding: AppleGrantBinding, key: Uuid, ciphertext: String) -> Result<Self> {
        if key.is_nil()
            || ciphertext.len() > MAX_ENVELOPE_BYTES
            || ciphertext
                .bytes()
                .any(|b| !b.is_ascii_alphanumeric() && !b"-_.".contains(&b))
        {
            return Err(Error::InvalidInput);
        }
        let parts: Vec<_> = ciphertext.split('.').collect();
        // Compact direct-key envelope only. Other algorithms/extra members still
        // require exact authenticated header selection before any decryption.
        if parts.len() != 5
            || !parts[1].is_empty()
            || [parts[0], parts[2], parts[3], parts[4]]
                .iter()
                .any(|v| v.is_empty())
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            binding,
            key,
            ciphertext,
        })
    }
    pub fn binding(&self) -> AppleGrantBinding {
        self.binding
    }
    pub fn key_id(&self) -> Uuid {
        self.key
    }
    pub fn ciphertext(&self) -> &str {
        &self.ciphertext
    }
}
impl fmt::Debug for AppleGrantEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppleGrantEnvelope([REDACTED])")
    }
}
