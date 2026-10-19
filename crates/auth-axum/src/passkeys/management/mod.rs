mod contract;
mod handlers;
mod routing;
mod types;

pub use contract::passkey_management_openapi;
pub use routing::experimental_passkey_management_router;

#[cfg(feature = "passkey-recovery-setup")]
pub(in crate::passkeys) use routing::configured_management_router;
