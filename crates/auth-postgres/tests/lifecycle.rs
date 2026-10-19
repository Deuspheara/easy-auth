mod support;

#[path = "lifecycle/account/mod.rs"]
mod account;
#[path = "lifecycle/email.rs"]
mod email;
#[path = "lifecycle/migration.rs"]
mod migration;
#[path = "lifecycle/notifications.rs"]
mod notifications;
#[cfg(feature = "passkeys")]
#[path = "lifecycle/passkeys/mod.rs"]
mod passkeys;
#[path = "lifecycle/passwords.rs"]
mod passwords;
#[path = "lifecycle/recovery.rs"]
mod recovery;
#[path = "lifecycle/sessions/mod.rs"]
mod sessions;

#[path = "lifecycle/audit/mod.rs"]
mod audit;
