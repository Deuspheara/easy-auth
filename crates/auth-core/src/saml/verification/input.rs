use crate::{Error, Result};
use std::fmt;
use zeroize::Zeroizing;

/// Maximum encoded POST SAMLResponse size for this deliberately narrow profile.
pub const MAX_POST_RESPONSE_BYTES: usize = 256 * 1024;

/// Untrusted base64 POST field. Parsing here establishes no protocol authority.
pub struct SamlPostResponse(pub(super) Zeroizing<String>);

impl SamlPostResponse {
    pub fn parse(encoded: String) -> Result<Self> {
        let encoded = Zeroizing::new(encoded);
        if encoded.is_empty() || encoded.len() > MAX_POST_RESPONSE_BYTES || !encoded.is_ascii() {
            return Err(Error::InvalidInput);
        }
        Ok(Self(encoded))
    }
}
impl fmt::Debug for SamlPostResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SamlPostResponse([REDACTED; untrusted])")
    }
}
