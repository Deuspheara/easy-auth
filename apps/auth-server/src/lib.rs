//! Validated server composition shared by the binary and embedded example.
mod application;
mod configuration;
mod notifications;
#[cfg(feature = "oidc-egress")]
mod oidc_http;
mod smtp;

pub use application::{ConfiguredApplication, configured_application};
pub use configuration::configured_auth;
pub use notifications::notification_worker;
#[cfg(feature = "oidc-egress")]
pub use oidc_http::OidcHttps;
