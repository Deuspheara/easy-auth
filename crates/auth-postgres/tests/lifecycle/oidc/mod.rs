#[cfg(feature = "apple")]
mod apple;
#[cfg(feature = "apple")]
#[path = "../../../../../tests/support/apple/provider.rs"]
mod apple_provider;
mod binding;
#[cfg(feature = "google")]
mod google;
#[cfg(feature = "google")]
#[path = "../../../../../tests/support/google/provider.rs"]
mod google_provider;
#[cfg(feature = "oidc-identities")]
mod identities;
#[cfg(feature = "oidc-identities")]
mod identity_policy;
#[cfg(feature = "oidc-identities")]
mod identity_policy_schema;
mod refresh;
mod setup;

#[cfg(feature = "oidc-verification")]
mod verification;
#[cfg(feature = "oidc-verification")]
mod verification_wait;
