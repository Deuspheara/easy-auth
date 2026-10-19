mod contract;
mod handlers;
mod routing;
mod schema;
mod types;

pub use contract::passkey_authentication_openapi;
#[cfg(feature = "passkey-signup")]
pub(super) use routing::authentication_routes;
pub use routing::experimental_passkey_router;
#[cfg(feature = "passkey-signup")]
pub(super) use schema::{WebAuthnAssertionResponse, WebAuthnRequestOptions};
