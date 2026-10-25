use super::super::input::{OidcIdToken, optional};
use crate::{Error, MAX_OIDC_DOCUMENT_BYTES, Result};
use serde::Deserialize;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

const MAX_UNUSED_TOKEN_BYTES: usize = 16 * 1024;
/// Unverified protected endpoint envelope, not a successful token/identity result.
pub struct OidcTokenResponse {
    status: u16,
    content_type: Option<String>,
    encoding: Option<String>,
    body: Zeroizing<Vec<u8>>,
}
impl OidcTokenResponse {
    pub fn new(
        status: u16,
        content_type: Option<String>,
        encoding: Option<String>,
        body: Vec<u8>,
    ) -> Result<Self> {
        let body = Zeroizing::new(body);
        if body.len() > MAX_OIDC_DOCUMENT_BYTES {
            return Err(Error::Unavailable);
        }
        Ok(Self {
            status,
            content_type,
            encoding,
            body,
        })
    }
    pub(in crate::oidc) fn json(self) -> Result<TokenResponseJson> {
        let mime = self
            .content_type
            .as_deref()
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        if !mime.eq_ignore_ascii_case("application/json")
            || self
                .encoding
                .as_deref()
                .is_some_and(|v| !v.eq_ignore_ascii_case("identity"))
        {
            return Err(Error::Unavailable);
        }
        Ok(TokenResponseJson {
            status: self.status,
            body: self.body,
        })
    }
    pub(in crate::oidc) fn id_token(self) -> Result<OidcIdToken> {
        let response = self.json()?;
        if matches!(response.status, 400 | 401) {
            #[derive(Deserialize)]
            struct Failure {
                error: String,
            }
            let failure: Failure =
                serde_json::from_slice(&response.body).map_err(|_| Error::Unavailable)?;
            return Err(
                if response.status == 400 && failure.error == "invalid_grant" {
                    Error::Unauthorized
                } else {
                    Error::Unavailable
                },
            );
        }
        if response.status != 200 {
            return Err(Error::Unavailable);
        }
        let mut wire: Success =
            serde_json::from_slice(&response.body).map_err(|_| Error::Unavailable)?;
        if wire.error.is_some()
            || !wire.token_type.eq_ignore_ascii_case("Bearer")
            || !valid_token(&wire.access_token)
            || wire.refresh_token.as_ref().is_some_and(|v| !valid_token(v))
        {
            return Err(Error::Unavailable);
        }
        OidcIdToken::parse(std::mem::take(&mut wire.id_token))
    }
}
pub(in crate::oidc) struct TokenResponseJson {
    pub status: u16,
    pub body: Zeroizing<Vec<u8>>,
}
impl fmt::Debug for OidcTokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcTokenResponse([REDACTED])")
    }
}
#[derive(Deserialize)]
struct Success {
    id_token: String,
    access_token: String,
    token_type: String,
    #[serde(default, deserialize_with = "optional")]
    refresh_token: Option<String>,
    #[serde(default, deserialize_with = "optional")]
    #[serde(rename = "expires_in")]
    _expires_in: Option<u64>,
    #[serde(default, deserialize_with = "optional")]
    error: Option<String>,
}
impl Drop for Success {
    fn drop(&mut self) {
        self.id_token.zeroize();
        self.access_token.zeroize();
        if let Some(value) = &mut self.refresh_token {
            value.zeroize();
        }
    }
}
fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_UNUSED_TOKEN_BYTES
        && value.bytes().all(|b| (0x20..=0x7e).contains(&b))
}
