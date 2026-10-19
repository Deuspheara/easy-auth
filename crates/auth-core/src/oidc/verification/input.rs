use super::policy::{MAX_KID_BYTES, OidcSigningAlgorithm};
use crate::{Error, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer};
use std::{fmt, sync::Arc};
use zeroize::Zeroizing;

const MAX_ID_TOKEN_BYTES: usize = 16 * 1024;
const MAX_ENCODED_HEADER_BYTES: usize = 2048;

/// Backend-only token input. No Clone/Serialize or raw diagnostic representation.
pub struct OidcIdToken(pub(super) Arc<Zeroizing<String>>);
impl OidcIdToken {
    pub fn parse(value: String) -> Result<Self> {
        let value = Zeroizing::new(value);
        if value.is_empty()
            || value.len() > MAX_ID_TOKEN_BYTES
            || !value.is_ascii()
            || value
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(Error::Unauthorized);
        }
        let token = Self(Arc::new(value));
        header(&token.0)?;
        Ok(token)
    }
}
impl fmt::Debug for OidcIdToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcIdToken([REDACTED])")
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Header {
    pub(super) alg: OidcSigningAlgorithm,
    pub(super) kid: String,
    #[serde(default, deserialize_with = "optional")]
    typ: Option<String>,
}

pub(super) fn header(token: &str) -> Result<Header> {
    let mut parts = token.split('.');
    let encoded = parts.next().ok_or(Error::Unauthorized)?;
    let payload = parts.next().ok_or(Error::Unauthorized)?;
    let signature = parts.next().ok_or(Error::Unauthorized)?;
    if parts.next().is_some()
        || [encoded, payload, signature]
            .iter()
            .any(|part| part.is_empty())
        || encoded.len() > MAX_ENCODED_HEADER_BYTES
    {
        return Err(Error::Unauthorized);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Error::Unauthorized)?;
    let value: Header = serde_json::from_slice(&bytes).map_err(|_| Error::Unauthorized)?;
    if value.kid.is_empty()
        || value.kid.len() > MAX_KID_BYTES
        || value.kid.chars().any(char::is_control)
        || value
            .typ
            .as_deref()
            .is_some_and(|kind| kind != "JWT" && kind != "application/jwt")
    {
        return Err(Error::Unauthorized);
    }
    Ok(value)
}

// Missing is allowed only where explicitly annotated; a present null is not a
// missing protocol member. Derived structs also reject duplicate known members.
pub(super) fn optional<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}
