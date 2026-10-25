use crate::{Error, Result};
use josekit::jwk::{
    KeyPair,
    alg::ec::{EcCurve, EcKeyPair},
};
use openssl::{nid::Nid, pkey::PKey};
use zeroize::Zeroizing;

const MAX_PRIVATE_PEM_BYTES: usize = 4096;

/// Operator-only input. The only signing operation is the fixed Apple secret;
/// neither private components nor an arbitrary-payload signer are exposed.
pub(super) struct SigningKey {
    pair: EcKeyPair,
}

impl SigningKey {
    pub(super) fn parse(input: String) -> Result<Self> {
        let input = Zeroizing::new(input);
        let begin = "-----BEGIN PRIVATE KEY-----";
        let end = "-----END PRIVATE KEY-----";
        if input.len() > MAX_PRIVATE_PEM_BYTES
            || !input.is_ascii()
            || !input
                .strip_prefix(begin)
                .is_some_and(|rest| rest.starts_with('\n') || rest.starts_with("\r\n"))
            || !input.trim_end_matches(['\r', '\n']).ends_with(end)
            || input.matches("-----BEGIN").count() != 1
            || input.matches("-----END").count() != 1
        {
            return Err(Error::InvalidInput);
        }
        let key = PKey::private_key_from_pem(input.as_bytes()).map_err(|_| Error::InvalidInput)?;
        let ec = key.ec_key().map_err(|_| Error::InvalidInput)?;
        if ec.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
            return Err(Error::InvalidInput);
        }
        ec.check_key().map_err(|_| Error::InvalidInput)?;
        let pair = EcKeyPair::from_pem(input.as_bytes(), Some(EcCurve::P256))
            .map_err(|_| Error::InvalidInput)?;
        Ok(Self { pair })
    }

    pub(super) fn sign(&self, key_id: &str, payload: &[u8]) -> Result<Zeroizing<String>> {
        let der = Zeroizing::new(self.pair.to_der_private_key());
        let signer = josekit::jws::ES256
            .signer_from_der(der.as_slice())
            .map_err(|_| Error::Unavailable)?;
        let mut header = josekit::jws::JwsHeader::new();
        header.set_algorithm("ES256");
        header.set_key_id(key_id);
        header.set_token_type("JWT");
        josekit::jws::serialize_compact(payload, &header, &signer)
            .map(Zeroizing::new)
            .map_err(|_| Error::Unavailable)
    }
}
