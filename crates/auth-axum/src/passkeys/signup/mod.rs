mod contract;
mod handlers;
mod routing;
mod types;

pub use contract::passkey_signup_openapi;
pub use routing::experimental_passkey_signup_router;

#[cfg(feature = "passkey-management")]
pub(super) use routing::signup_routes;
