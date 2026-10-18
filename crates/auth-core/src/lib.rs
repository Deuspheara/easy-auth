//! Shared authentication use cases. HTTP and SQL implementations live outside this crate.
mod audit;
mod auth;
mod email;
mod error;
mod identity;
mod notifications;
mod password;
mod ports;
mod secret;
mod sessions;

pub use audit::AuditEvent;
pub use auth::Auth;
pub use email::normalize_email;
pub use error::{Error, Result};
pub use identity::User;
pub use notifications::{SecurityNotice, SecurityNoticeKind};
pub use password::{Password, PasswordService};
pub use ports::{EmailDelivery, Repository};
pub use secret::{Secret, Verifier};
pub use sessions::{SessionInfo, SessionPage};
