use super::super::metadata::MAX_JWKS_KEYS;
use super::{
    input::{Header, optional},
    policy::{MAX_KID_BYTES, OidcSigningAlgorithm},
};
use crate::{Error, OidcJwksDocument, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use josekit::{
    jwk::Jwk,
    jws::{ES256, JwsVerifier, PS256, RS256},
};
use serde::Deserialize;
use std::collections::HashSet;

const MIN_RSA_BYTES: usize = 256;
const MAX_RSA_BYTES: usize = 1024;
const MIN_RSA_BITS: usize = 2048;
const MAX_RSA_BITS: usize = 8192;
const MAX_RSA_EXPONENT_BYTES: usize = 8;
const P256_COORDINATE_BYTES: usize = 32;

#[derive(Deserialize)]
struct Set {
    keys: Vec<Key>,
}
#[derive(Deserialize)]
struct Key {
    kty: String,
    #[serde(default, deserialize_with = "optional")]
    kid: Option<String>,
    #[serde(default, deserialize_with = "optional")]
    alg: Option<String>,
    #[serde(default, rename = "use", deserialize_with = "optional")]
    use_: Option<String>,
    #[serde(default, deserialize_with = "optional")]
    key_ops: Option<Vec<String>>,
    #[serde(default, deserialize_with = "optional")]
    n: Option<String>,
    #[serde(default, deserialize_with = "optional")]
    e: Option<String>,
    #[serde(default, deserialize_with = "optional")]
    crv: Option<String>,
    #[serde(default, deserialize_with = "optional")]
    x: Option<String>,
    #[serde(default, deserialize_with = "optional")]
    y: Option<String>,
}

pub(super) fn select(
    document: &OidcJwksDocument,
    header: &Header,
) -> Result<Option<Box<dyn JwsVerifier>>> {
    // Derived fields preserve duplicate-member rejection before any lossy map.
    let set: Set = serde_json::from_slice(document.as_bytes()).map_err(|_| Error::Unavailable)?;
    if set.keys.is_empty() || set.keys.len() > MAX_JWKS_KEYS {
        return Err(Error::Unavailable);
    }
    let mut ids = HashSet::new();
    for key in &set.keys {
        if let Some(id) = &key.kid
            && (id.is_empty()
                || id.len() > MAX_KID_BYTES
                || id.chars().any(char::is_control)
                || !ids.insert(id))
        {
            return Err(Error::Unavailable);
        }
    }
    let Some(key) = set
        .keys
        .iter()
        .find(|key| key.kid.as_deref() == Some(&header.kid))
    else {
        return Ok(None);
    };
    key.check_verification_use(header.alg)?;
    let public = match header.alg {
        OidcSigningAlgorithm::RS256 | OidcSigningAlgorithm::PS256 => {
            let n = material(key.n.as_deref(), MIN_RSA_BYTES, MAX_RSA_BYTES)?;
            let e = material(key.e.as_deref(), 1, MAX_RSA_EXPONENT_BYTES)?;
            let bits = n.len() * 8 - n[0].leading_zeros() as usize;
            if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&bits)
                || n[0] == 0
                || e.last().is_none_or(|last| last % 2 == 0)
                || (e.len() == 1 && e[0] < 3)
            {
                return Err(Error::Unavailable);
            }
            serde_json::json!({"kty":"RSA", "n":key.n, "e":key.e})
        }
        OidcSigningAlgorithm::ES256 => {
            material(
                key.x.as_deref(),
                P256_COORDINATE_BYTES,
                P256_COORDINATE_BYTES,
            )?;
            material(
                key.y.as_deref(),
                P256_COORDINATE_BYTES,
                P256_COORDINATE_BYTES,
            )?;
            serde_json::json!({"kty":"EC", "crv":"P-256", "x":key.x, "y":key.y})
        }
    };
    // Only the validated public components enter the established verifier. No
    // embedded certificate, remote URL, private field or algorithm inference.
    let jwk = Jwk::from_map(public.as_object().ok_or(Error::Unavailable)?.clone())
        .map_err(|_| Error::Unavailable)?;
    let verifier: Box<dyn JwsVerifier> = match header.alg {
        OidcSigningAlgorithm::RS256 => Box::new(
            RS256
                .verifier_from_jwk(&jwk)
                .map_err(|_| Error::Unavailable)?,
        ),
        OidcSigningAlgorithm::PS256 => Box::new(
            PS256
                .verifier_from_jwk(&jwk)
                .map_err(|_| Error::Unavailable)?,
        ),
        OidcSigningAlgorithm::ES256 => Box::new(
            ES256
                .verifier_from_jwk(&jwk)
                .map_err(|_| Error::Unavailable)?,
        ),
    };
    Ok(Some(verifier))
}
impl Key {
    fn check_verification_use(&self, algorithm: OidcSigningAlgorithm) -> Result<()> {
        const MAX_KEY_OPERATIONS: usize = 8;
        if self.key_ops.as_ref().is_some_and(|ops| {
            ops.len() > MAX_KEY_OPERATIONS
                || ops
                    .iter()
                    .enumerate()
                    .any(|(index, value)| ops[..index].contains(value))
        }) {
            return Err(Error::Unavailable);
        }
        let compatible_type = match algorithm {
            OidcSigningAlgorithm::RS256 | OidcSigningAlgorithm::PS256 => self.kty == "RSA",
            OidcSigningAlgorithm::ES256 => self.kty == "EC" && self.crv.as_deref() == Some("P-256"),
        };
        // A valid key can be unusable for this token. That is token rejection,
        // distinct from a malformed provider document or cryptographic component.
        if !compatible_type
            || self
                .alg
                .as_deref()
                .is_some_and(|alg| alg != algorithm.name())
            || self.use_.as_deref().is_some_and(|value| value != "sig")
            || self
                .key_ops
                .as_ref()
                .is_some_and(|ops| ops.as_slice() != ["verify"])
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}

fn material(value: Option<&str>, min: usize, max: usize) -> Result<Vec<u8>> {
    let value = value.ok_or(Error::Unavailable)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Error::Unavailable)?;
    if !(min..=max).contains(&decoded.len()) || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(Error::Unavailable);
    }
    Ok(decoded)
}
