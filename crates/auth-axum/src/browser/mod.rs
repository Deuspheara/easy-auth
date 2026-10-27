mod boundary;
mod config;
mod cookies;
mod headers;

pub(crate) use boundary::boundary;
pub use config::BrowserConfig;
#[cfg(any(
    feature = "passkey-enrollment",
    feature = "oidc-account-deletion",
    feature = "issuer-consent-web"
))]
pub(crate) use cookies::read_optional_cookie;
#[cfg(any(feature = "oidc-web", feature = "saml-web", feature = "apple-web"))]
pub(crate) use cookies::require_anonymous;
pub(crate) use cookies::{clear_auth_cookies, read_cookie};

#[cfg(any(feature = "saml-web", feature = "apple-web"))]
pub(crate) use boundary::post_delivery_boundary;
#[cfg(any(feature = "saml-web", feature = "issuer-consent-web"))]
pub(crate) use cookies::read_optional_cookie_value;

#[cfg(test)]
mod tests;

#[cfg(feature = "issuer-web")]
pub(crate) use boundary::client_token_boundary;
