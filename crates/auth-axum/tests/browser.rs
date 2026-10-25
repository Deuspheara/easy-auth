mod support;

#[path = "browser/account.rs"]
mod account;
#[path = "browser/boundary.rs"]
mod boundary;
#[path = "browser/contract.rs"]
mod contract;
#[path = "browser/email.rs"]
mod email;
#[path = "browser/passwords.rs"]
mod passwords;
#[path = "browser/providers.rs"]
mod providers;
#[path = "browser/recovery.rs"]
mod recovery;
#[path = "browser/reference_ui.rs"]
mod reference_ui;

#[path = "browser/sessions/mod.rs"]
mod sessions;

#[path = "browser/audit.rs"]
mod audit;
#[cfg(feature = "passkey-authentication")]
#[path = "browser/passkey_authentication/mod.rs"]
mod passkey_authentication;
#[cfg(feature = "passkey-signup")]
#[path = "browser/passkey_signup/mod.rs"]
mod passkey_signup;
#[cfg(feature = "passkey-enrollment")]
#[path = "browser/passkeys.rs"]
mod passkeys;

#[cfg(feature = "passkey-management")]
#[path = "browser/passkey_management/mod.rs"]
mod passkey_management;

#[cfg(feature = "oidc-account-deletion")]
#[path = "browser/oidc_deletion/mod.rs"]
mod oidc_deletion;

#[cfg(feature = "oidc-web")]
#[path = "browser/oidc_web/mod.rs"]
mod oidc_web;

#[cfg(feature = "google-web")]
#[path = "browser/google_web/mod.rs"]
mod google_web;

#[cfg(feature = "apple-web")]
#[path = "browser/apple_web/mod.rs"]
mod apple_web;

#[cfg(feature = "saml-web")]
#[path = "browser/saml/mod.rs"]
mod saml;

#[cfg(feature = "issuer-consent-web")]
#[path = "browser/issuer_consent/mod.rs"]
mod issuer_consent;

#[cfg(feature = "issuer-web")]
#[path = "browser/issuer_web/mod.rs"]
mod issuer_web;

#[cfg(all(feature = "issuer-native-consent-web", feature = "issuer-web"))]
#[path = "browser/issuer_native_consent/mod.rs"]
mod issuer_native_consent;

#[cfg(feature = "issuer-native-web")]
#[path = "browser/issuer_native_web/mod.rs"]
mod issuer_native_web;

#[cfg(feature = "apple-web")]
#[path = "../../../tests/support/apple/provider.rs"]
mod apple_provider;
#[cfg(feature = "google-web")]
#[path = "../../../tests/support/google/provider.rs"]
mod google_provider;
