//! Explicit leaf-certificate pinning configuration; no identity/session authority.
mod pin;
mod trust;

pub use pin::SamlPinnedCertificate;
pub use trust::{MAX_SAML_PINNED_CERTIFICATES, SamlCertificateTrust};

#[cfg(test)]
mod tests;
