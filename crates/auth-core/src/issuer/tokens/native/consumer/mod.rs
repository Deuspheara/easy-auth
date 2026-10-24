//! Explicit authenticated consumers of native audiences; no local session proof.
mod access;
mod policy;
mod service;
#[cfg(test)]
mod tests;

pub use access::{IssuerNativeAccessData, IssuerNativeActiveAccess};
pub use policy::IssuerNativeConsumerPolicy;
pub use service::{IssuerNativeIntrospection, IssuerNativeIntrospectionRepository};
