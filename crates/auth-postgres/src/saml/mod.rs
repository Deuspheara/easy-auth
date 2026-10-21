#[cfg(feature = "saml-certificates")]
mod certificates;
mod configuration;
mod consumption;
mod requests;

#[cfg(feature = "saml-verification")]
mod verification;

#[cfg(feature = "saml-identities")]
pub(crate) mod identity_policy;

#[cfg(feature = "saml-identities")]
mod identities;

#[cfg(feature = "saml-identities")]
pub(crate) mod replay;
