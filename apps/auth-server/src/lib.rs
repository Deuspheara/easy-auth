//! Validated server composition shared by the binary and embedded example.
mod configuration;
mod notifications;
mod smtp;

pub use configuration::configured_auth;
pub use notifications::notification_worker;
