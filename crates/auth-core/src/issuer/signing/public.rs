use super::{ALGORITHM, MAX_PUBLIC_JWK_BYTES, MAX_RSA_BITS, MAX_RSA_EXPONENT_BYTES, MIN_RSA_BITS};
use crate::{Error, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::Value;
use std::fmt;
use uuid::Uuid;

/// Validated public-only RS256 metadata. It is not signing authority; the current
/// registry and exact protected private-key match must still gate issuance.
#[derive(Clone, Eq, PartialEq)]
pub struct IssuerPublicKey {
    id: Uuid,
    document: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicDocument {
    kid: String,
    kty: String,
    n: String,
    e: String,
    alg: String,
    #[serde(rename = "use")]
    use_: String,
    key_ops: Vec<String>,
}
impl IssuerPublicKey {
    /// Strict raw JSON admission preserves duplicate-member rejection before any
    /// map conversion. Private fields, certificates and key URLs are unsupported.
    pub fn from_json(input: &[u8]) -> Result<Self> {
        if input.len() > MAX_PUBLIC_JWK_BYTES {
            return Err(Error::InvalidInput);
        }
        let parsed: PublicDocument =
            serde_json::from_slice(input).map_err(|_| Error::InvalidInput)?;
        let id = Uuid::parse_str(&parsed.kid).map_err(|_| Error::InvalidInput)?;
        if id.is_nil()
            || id.to_string() != parsed.kid
            || parsed.kty != "RSA"
            || parsed.alg != ALGORITHM
            || parsed.use_ != "sig"
            || parsed.key_ops != ["verify"]
        {
            return Err(Error::InvalidInput);
        }
        let modulus = integer(&parsed.n, (MAX_RSA_BITS / 8) as usize)?;
        let bits = (modulus.len() as u32 - 1) * 8 + (8 - modulus[0].leading_zeros());
        // Outbound keys use a bounded ordinary unsigned exponent. No custom
        // signature, primality test or cryptographic arithmetic is implemented.
        let exponent = integer(&parsed.e, MAX_RSA_EXPONENT_BYTES)?;
        if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&bits)
            || exponent.last().is_none_or(|n| n % 2 == 0)
            || (exponent.len() == 1 && exponent[0] < 3)
        {
            return Err(Error::InvalidInput);
        }
        let document = serde_json::from_slice(input).map_err(|_| Error::InvalidInput)?;
        Ok(Self { id, document })
    }
    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn document(&self) -> &Value {
        &self.document
    }
}
impl fmt::Debug for IssuerPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuerPublicKey")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}
fn integer(encoded: &str, max: usize) -> Result<Vec<u8>> {
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Error::InvalidInput)?;
    if decoded.is_empty()
        || decoded.len() > max
        || decoded[0] == 0
        || URL_SAFE_NO_PAD.encode(&decoded) != encoded
    {
        return Err(Error::InvalidInput);
    }
    Ok(decoded)
}
