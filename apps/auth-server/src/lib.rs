//! Validated server composition shared by the binary and embedded example.
mod administration;
mod application;
mod configuration;
#[cfg(feature = "google-desktop")]
mod google_desktop;
#[cfg(feature = "issuer-signing")]
mod issuer_key;
mod notifications;
#[cfg(feature = "oidc-egress")]
mod oidc_http;
mod smtp;

pub use administration::migrate_database;
pub use application::{ConfiguredApplication, configured_application};
pub use configuration::configured_auth;
#[cfg(feature = "google-desktop")]
pub use google_desktop::{GoogleDesktopCallback, GoogleDesktopError, GoogleDesktopListener};
#[cfg(feature = "google-desktop-launch")]
pub use google_desktop::{GoogleDesktopLaunchError, GoogleDesktopSignIn, GoogleDesktopSignInError};
#[cfg(feature = "issuer-signing")]
pub use issuer_key::load_issuer_signing_key;
pub use notifications::notification_worker;
#[cfg(feature = "oidc-egress")]
pub use oidc_http::OidcHttps;
