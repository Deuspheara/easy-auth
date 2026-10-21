#[cfg(feature = "saml-certificates")]
mod certificates;
mod configuration;
mod consumption;
mod requests;

#[cfg(feature = "saml-verification")]
mod verification;
