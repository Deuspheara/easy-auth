//! Closed audit event shape, target metadata and actor attribution.
mod attribution;
mod event;
mod metadata;
mod native;

pub use event::AuditEvent;
pub use native::{
    IssuerNativeCredentialAction, IssuerNativeCredentialEvent, IssuerNativeCredentialKind,
};
