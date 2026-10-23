use super::{
    ALGORITHM, IssuerPublicKey, MAX_PRIVATE_PEM_BYTES, MAX_RSA_BITS, MAX_RSA_EXPONENT_BYTES,
    MIN_RSA_BITS,
};
use crate::{Error, Result};
use josekit::jwk::{KeyPair, alg::rsa::RsaKeyPair};
use openssl::pkey::PKey;
use std::fmt;
use uuid::Uuid;
use zeroize::Zeroizing;

const PRIVATE_KEY_LABEL: &str = "PRIVATE KEY";
/// Opaque validated RSA input. No private projection, Clone, serialization,
/// default key, algorithm choice or public arbitrary-payload signing API.
pub struct IssuerSigningKey {
    id: Uuid,
    pair: RsaKeyPair,
}
impl IssuerSigningKey {
    /// Trusted operator input only, never a token/request field. The embedding
    /// must use protected input; native dependency copies are not claimed erased.
    pub fn from_pkcs8_pem(id: Uuid, input: String) -> Result<Self> {
        let input = Zeroizing::new(input);
        let trimmed = input.trim_end_matches(['\r', '\n']);
        let begin = format!("-----BEGIN {PRIVATE_KEY_LABEL}-----");
        let end = format!("-----END {PRIVATE_KEY_LABEL}-----");
        let opening_line = input.strip_prefix(&begin);
        if id.is_nil()
            || input.len() > MAX_PRIVATE_PEM_BYTES
            || !input.is_ascii()
            || !opening_line.is_some_and(|rest| rest.starts_with('\n') || rest.starts_with("\r\n"))
            || !trimmed.ends_with(&end)
            || input.matches("-----BEGIN").count() != 1
            || input.matches("-----END").count() != 1
        {
            return Err(Error::InvalidInput);
        }
        check_private(input.as_bytes())?;
        let pair = RsaKeyPair::from_pem(input.as_bytes()).map_err(|_| Error::InvalidInput)?;
        let key = Self { id, pair };
        key.public_key()?;
        Ok(key)
    }
    pub(super) fn sign(&self, payload: &[u8]) -> Result<Zeroizing<String>> {
        let der = Zeroizing::new(self.pair.to_der_private_key());
        let signer = josekit::jws::RS256
            .signer_from_der(der.as_slice())
            .map_err(|_| Error::Unavailable)?;
        let mut header = josekit::jws::JwsHeader::new();
        header.set_algorithm(ALGORITHM);
        header.set_key_id(self.id.to_string());
        header.set_token_type("JWT");
        josekit::jws::serialize_compact(payload, &header, &signer)
            .map(Zeroizing::new)
            .map_err(|_| Error::Unavailable)
    }
    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn public_key(&self) -> Result<IssuerPublicKey> {
        let public = self.pair.to_jwk_public_key();
        // Deliberate allowlist: never serialize the private JWK/key pair, even if
        // future library metadata gains additional fields.
        let value = serde_json::json!({"kid":self.id.to_string(),"kty":"RSA","n":public.parameter("n"),"e":public.parameter("e"),"alg":ALGORITHM,"use":"sig","key_ops":["verify"]});
        let bytes = serde_json::to_vec(&value).map_err(|_| Error::Unavailable)?;
        IssuerPublicKey::from_json(&bytes).map_err(|_| Error::Unavailable)
    }
}
impl fmt::Debug for IssuerSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuerSigningKey([REDACTED])")
    }
}
fn check_private(input: &[u8]) -> Result<()> {
    let key = PKey::private_key_from_pem(input).map_err(|_| Error::InvalidInput)?;
    let rsa = key.rsa().map_err(|_| Error::InvalidInput)?;
    let bits = rsa.n().num_bits() as u32;
    if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&bits)
        || rsa.e().num_bits() as usize > MAX_RSA_EXPONENT_BYTES * 8
    {
        return Err(Error::InvalidInput);
    }
    // Bound every supplied component before the established native key check.
    // This is input sizing, not a replacement for library RSA validation.
    if [
        Some(rsa.d()),
        rsa.p(),
        rsa.q(),
        rsa.dmp1(),
        rsa.dmq1(),
        rsa.iqmp(),
    ]
    .into_iter()
    .flatten()
    .any(|part| part.num_bits() as u32 > MAX_RSA_BITS)
        || !rsa.check_key().map_err(|_| Error::InvalidInput)?
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
