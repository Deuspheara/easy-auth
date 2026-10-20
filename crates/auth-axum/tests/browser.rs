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
#[path = "browser/recovery.rs"]
mod recovery;

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
