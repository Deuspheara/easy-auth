mod boundary;
mod config;
mod cookies;

pub(crate) use boundary::boundary;
pub use config::BrowserConfig;
#[cfg(any(feature = "passkey-enrollment", feature = "oidc-account-deletion"))]
pub(crate) use cookies::read_optional_cookie;
#[cfg(feature = "oidc-web")]
pub(crate) use cookies::require_anonymous;
pub(crate) use cookies::{clear_auth_cookies, read_cookie};

#[cfg(test)]
mod tests;
