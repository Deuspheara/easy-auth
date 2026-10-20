mod mapped;
mod policy;
mod signin;

pub use mapped::OidcMappedIdentity;
pub use policy::{OidcDisplayNameClaim, OidcIdentityPolicy, OidcJitPolicy};
pub use signin::{OidcIdentityRepository, OidcSignIn};

const MAX_DISPLAY_NAME_BYTES: usize = 256;

// Matches the existing local display-name storage bound. This is presentation
// policy only; neither this field nor provider email identifies a local owner.
pub(crate) fn usable_display_name(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_DISPLAY_NAME_BYTES
        && !value.chars().any(char::is_control)
}
