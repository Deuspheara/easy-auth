mod support;

#[path = "lifecycle/deadlines/mod.rs"]
mod deadlines;

#[path = "lifecycle/account/mod.rs"]
mod account;
#[path = "lifecycle/email.rs"]
mod email;
#[path = "lifecycle/migration.rs"]
mod migration;
#[path = "lifecycle/notifications.rs"]
mod notifications;
#[cfg(feature = "oauth-transactions")]
#[path = "lifecycle/oauth/mod.rs"]
mod oauth;
#[cfg(feature = "oidc-egress")]
#[path = "lifecycle/oidc/mod.rs"]
mod oidc;
#[cfg(feature = "passkeys")]
#[path = "lifecycle/passkeys/mod.rs"]
mod passkeys;
#[path = "lifecycle/passwords.rs"]
mod passwords;
#[path = "lifecycle/providers.rs"]
mod providers;
#[path = "lifecycle/recovery.rs"]
mod recovery;
#[cfg(feature = "saml-requests")]
#[path = "lifecycle/saml/mod.rs"]
mod saml;
#[path = "lifecycle/schema/mod.rs"]
mod schema;
#[path = "lifecycle/sessions/mod.rs"]
mod sessions;

#[path = "lifecycle/audit/mod.rs"]
mod audit;

#[path = "lifecycle/identity/mod.rs"]
mod identity;

#[cfg(feature = "issuer-clients")]
#[path = "lifecycle/issuer/mod.rs"]
mod issuer;

#[cfg(feature = "issuer-codes")]
#[path = "lifecycle/issuer_codes/mod.rs"]
mod issuer_codes;

#[cfg(feature = "issuer-signing")]
#[path = "lifecycle/issuer_signing/mod.rs"]
mod issuer_signing;

#[cfg(feature = "issuer-native-refresh")]
#[path = "lifecycle/issuer_native_refresh/mod.rs"]
mod issuer_native_refresh;
