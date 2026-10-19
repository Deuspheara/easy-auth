use crate::{Error, Result};

/// Trusted adapters call this after locking and validating the exact live/fresh
/// owner/session. `owns_passkey` covers the owner's entire realm, not only one RP.
/// Registration does not change account policy or prove passkey authentication.
pub fn authorize_passkey_enrollment(authentication_method: &str, owns_passkey: bool) -> Result<()> {
    match authentication_method {
        "passkey" => Ok(()),
        "email" | "password" if !owns_passkey => Ok(()),
        _ => Err(Error::Unauthorized),
    }
}
