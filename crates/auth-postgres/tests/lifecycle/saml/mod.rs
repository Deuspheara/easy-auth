mod admission;
#[cfg(feature = "saml-certificates")]
mod certificates;
mod configuration;
mod consumption;
mod requests;
mod setup;

#[cfg(feature = "saml-verification")]
mod verification;

#[cfg(feature = "saml-verification")]
mod signed_idp;
