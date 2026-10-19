//! Same-origin browser transport, shared by embedding and the standalone service.
mod browser;
mod contract;
mod error;
mod handlers;
#[cfg(feature = "passkey-enrollment")]
mod passkeys;
mod router;

use auth_core::Auth;
pub use browser::BrowserConfig;
pub use contract::openapi;
pub use handlers::sessions::authenticate;
#[cfg(feature = "passkey-enrollment")]
pub use passkeys::{experimental_passkey_enrollment_router, passkey_enrollment_openapi};
pub use router::router;
