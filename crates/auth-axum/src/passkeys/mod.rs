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
#[cfg(feature = "passkey-signup")]
mod email_attachment;
#[cfg(feature = "passkey-signup")]
mod signup;
#[cfg(feature = "passkey-signup")]
pub use signup::{experimental_passkey_signup_router, passkey_signup_openapi};

#[cfg(feature = "passkey-management")]
mod management;
#[cfg(feature = "passkey-management")]
pub use management::{experimental_passkey_management_router, passkey_management_openapi};
