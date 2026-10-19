use crate::{Error, Result};
use std::fmt;
use zeroize::Zeroizing;

const MAX_CLIENT_SECRET_BYTES: usize = 4096;
pub struct OidcClientSecret(pub(super) Zeroizing<String>);
impl OidcClientSecret {
    pub fn parse(value: String) -> Result<Self> {
        let value = Zeroizing::new(value);
        if value.is_empty()
            || value.len() > MAX_CLIENT_SECRET_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self(value))
    }
}
impl fmt::Debug for OidcClientSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcClientSecret([REDACTED])")
    }
}

/// Explicit registered client method. No discovery-selected downgrade/fallback.
pub enum OidcClientAuthentication {
    Public,
    ClientSecretBasic(OidcClientSecret),
    ClientSecretPost(OidcClientSecret),
}
impl OidcClientAuthentication {
    pub(super) fn method(&self) -> &'static str {
        match self {
            Self::Public => "none",
            Self::ClientSecretBasic(_) => "client_secret_basic",
            Self::ClientSecretPost(_) => "client_secret_post",
        }
    }
}
impl fmt::Debug for OidcClientAuthentication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcClientAuthentication([REDACTED])")
    }
}
