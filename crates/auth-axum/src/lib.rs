//! Same-origin browser transport, shared by embedding and the standalone service.
mod browser;
mod contract;
mod error;
mod handlers;
mod router;

use auth_core::Auth;
pub use browser::BrowserConfig;
pub use contract::openapi;
pub use handlers::sessions::authenticate;
pub use router::router;
