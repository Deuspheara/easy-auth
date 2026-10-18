use crate::{Error, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroize;

pub type Verifier = [u8; 32];
/// A canonical 256-bit bearer secret. Intentionally neither Serialize nor Clone.
pub struct Secret(String);
impl Secret {
    pub fn generate() -> Result<Self> {
        let mut bytes = [0; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| Error::Unavailable)?;
        let result = Self(URL_SAFE_NO_PAD.encode(bytes));
        bytes.zeroize();
        Ok(result)
    }
    pub fn parse(value: String) -> Result<Self> {
        if value.len() != 43 {
            return Err(Error::Unauthorized);
        }
        let mut bytes = URL_SAFE_NO_PAD
            .decode(&value)
            .map_err(|_| Error::Unauthorized)?;
        let canonical = bytes.len() == 32 && URL_SAFE_NO_PAD.encode(&bytes) == value;
        bytes.zeroize();
        if !canonical {
            return Err(Error::Unauthorized);
        }
        Ok(Self(value))
    }
    /// Expose only at the transport boundary. Never log this value.
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn verifier(&self) -> Verifier {
        Sha256::digest(self.0.as_bytes()).into()
    }
}
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}
impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tokens_are_canonical_redacted_and_high_entropy() {
        let a = Secret::generate().unwrap();
        let b = Secret::generate().unwrap();
        assert_eq!(a.expose().len(), 43);
        assert_ne!(a.verifier(), b.verifier());
        assert_eq!(
            Secret::parse(a.expose().to_owned()).unwrap().verifier(),
            a.verifier()
        );
        assert_eq!(format!("{a:?}"), "Secret([REDACTED])");
        for invalid in ["x".repeat(42), "!".repeat(43), "A".repeat(42) + "B"] {
            assert!(Secret::parse(invalid).is_err());
        }
    }
}
