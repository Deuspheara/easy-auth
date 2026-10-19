mod boundary;
mod config;
mod cookies;

pub(crate) use boundary::boundary;
pub use config::BrowserConfig;
#[cfg(feature = "passkey-enrollment")]
pub(crate) use cookies::read_optional_cookie;
pub(crate) use cookies::{clear_auth_cookies, read_cookie};

#[cfg(test)]
mod tests;
