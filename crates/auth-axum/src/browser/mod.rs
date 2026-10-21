mod boundary;
mod config;
mod cookies;

pub(crate) use boundary::boundary;
pub use config::BrowserConfig;
#[cfg(any(feature = "passkey-enrollment", feature = "oidc-account-deletion"))]
pub(crate) use cookies::read_optional_cookie;
#[cfg(any(feature = "oidc-web", feature = "saml-web"))]
pub(crate) use cookies::require_anonymous;
pub(crate) use cookies::{clear_auth_cookies, read_cookie};

#[cfg(feature = "saml-web")]
pub(crate) use boundary::post_delivery_boundary;
#[cfg(feature = "saml-web")]
pub(crate) use cookies::read_optional_cookie_value;

#[cfg(test)]
mod tests;
