#[cfg(feature = "issuer-codes")]
mod authorization;
#[cfg(feature = "issuer-native-refresh")]
mod delegation;
#[cfg(feature = "issuer-native-refresh")]
pub(crate) use delegation::DelegatedSessionSnapshot;
mod linked_providers;
mod listing;
#[cfg(feature = "issuer-codes")]
pub(crate) use authorization::{FreshSessionAuthorization, FreshSessionSnapshot};
mod logout;
#[cfg(feature = "oidc-identities")]
mod oidc;
mod ownership;
mod revocation;
mod source;
mod validation;

#[cfg(any(feature = "oidc-identities", feature = "saml-identities"))]
mod provider_listing;

#[cfg(feature = "saml-identities")]
mod saml;
