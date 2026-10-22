//! Outbound issuer configuration only; no token, consent or authentication grant.
mod redirects;
mod registration;
#[cfg(test)]
mod tests;

pub use redirects::{MAX_ISSUER_REDIRECT_BYTES, MAX_ISSUER_REDIRECTS};
pub use registration::{IssuerClientKind, IssuerClientRegistration};
