use super::AppleRevocationFailure;
use crate::{Error, Result};
use serde::Deserialize;
use std::fmt;
use zeroize::Zeroizing;
const MAX_REVOCATION_RESPONSE_BYTES: usize = 16 * 1024;
pub struct AppleRevocationResponse {
    status: u16,
    content_type: Option<String>,
    encoding: Option<String>,
    body: Zeroizing<Vec<u8>>,
}
impl AppleRevocationResponse {
    pub fn new(
        status: u16,
        content_type: Option<String>,
        encoding: Option<String>,
        body: Vec<u8>,
    ) -> Result<Self> {
        let body = Zeroizing::new(body);
        if body.len() > MAX_REVOCATION_RESPONSE_BYTES {
            return Err(Error::Unavailable);
        }
        Ok(Self {
            status,
            content_type,
            encoding,
            body,
        })
    }
    pub(super) fn verify(self) -> std::result::Result<(), AppleRevocationFailure> {
        use AppleRevocationFailure as F;
        if self
            .encoding
            .as_deref()
            .is_some_and(|v| !v.eq_ignore_ascii_case("identity"))
        {
            return Err(F::Provider);
        }
        if self.status == 200 && self.body.is_empty() {
            return Ok(());
        }
        // A200 error/nonempty body is not proof of remote success.400 invalid_grant
        // is also not silently converted to the documented already-invalid200.
        if matches!(self.status, 400 | 401)
            && self.content_type.as_deref().is_some_and(|v| {
                v.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("application/json")
            })
        {
            #[derive(Deserialize)]
            struct Failure {
                error: String,
            }
            if let Ok(failure) = serde_json::from_slice::<Failure>(&self.body)
                && matches!(
                    failure.error.as_str(),
                    "invalid_client" | "unauthorized_client" | "invalid_request"
                )
            {
                return Err(F::Configuration);
            }
        }
        Err(F::Provider)
    }
}
impl fmt::Debug for AppleRevocationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppleRevocationResponse([REDACTED])")
    }
}
