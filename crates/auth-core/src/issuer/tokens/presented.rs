use crate::{Error, Result, Secret, Verifier};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroizing;

const MAX_PRESENTED_TOKEN_BYTES: usize = 1024;
/// A bounded presented opaque credential, not a minted-token or authority proof.
/// Unknown syntactically valid strings can reach authenticated status operations
/// without requiring the issuer's canonical Secret encoding. Retains only a hash.
pub struct IssuerPresentedToken(Verifier);
impl IssuerPresentedToken {
    pub fn parse(input: String) -> Result<Self> {
        let input = Zeroizing::new(input);
        if input.is_empty()
            || input.len() > MAX_PRESENTED_TOKEN_BYTES
            || !input.bytes().all(|b| (0x20..=0x7e).contains(&b))
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self(Sha256::digest(input.as_bytes()).into()))
    }
    pub(super) fn verifier(&self) -> Verifier {
        self.0
    }
}
impl From<&Secret> for IssuerPresentedToken {
    fn from(secret: &Secret) -> Self {
        Self(secret.verifier())
    }
}
impl fmt::Debug for IssuerPresentedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuerPresentedToken([REDACTED])")
    }
}
