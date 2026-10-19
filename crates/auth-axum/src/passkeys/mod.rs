mod contract;
mod handlers;
mod routing;
mod schema;
mod types;

pub use contract::passkey_enrollment_openapi;
pub use routing::experimental_passkey_enrollment_router;
#[cfg(feature = "passkey-authentication")]
mod authentication;
#[cfg(feature = "passkey-authentication")]
pub use authentication::{experimental_passkey_router, passkey_authentication_openapi};
