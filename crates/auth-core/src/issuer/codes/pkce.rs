use crate::{Error, Result, Verifier};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroizing;

/// RFC7636 verifier, distinct from easy-auth's fixed-size opaque bearer Secret.
/// Accept the complete43–128 unreserved-character range; never persist/log it.
pub struct IssuerPkceVerifier(Zeroizing<String>);
impl IssuerPkceVerifier {
    pub fn parse(value: String) -> Result<Self> {
        let value = Zeroizing::new(value);
        if !(43..=128).contains(&value.len())
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self(value))
    }
    pub fn s256_digest(&self) -> Verifier {
        Sha256::digest(self.0.as_bytes()).into()
    }
    pub fn challenge(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.s256_digest())
    }
}
impl fmt::Debug for IssuerPkceVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuerPkceVerifier([REDACTED])")
    }
}
pub(super) fn challenge(value: &str) -> Result<Verifier> {
    if value.len() != 43 {
        return Err(Error::InvalidInput);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Error::InvalidInput)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(Error::InvalidInput);
    }
    bytes.try_into().map_err(|_| Error::InvalidInput)
}
