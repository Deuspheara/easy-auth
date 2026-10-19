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
#[cfg(feature = "passkey-authentication")]
pub use passkeys::{experimental_passkey_router, passkey_authentication_openapi};
#[cfg(feature = "passkey-signup")]
pub use passkeys::{experimental_passkey_signup_router, passkey_signup_openapi};
pub use router::router;

#[cfg(feature = "passkey-management")]
pub use passkeys::{experimental_passkey_management_router, passkey_management_openapi};

#[cfg(feature = "passkey-recovery-setup")]
pub use passkeys::{experimental_passkey_recovery_setup_router, passkey_recovery_setup_openapi};
