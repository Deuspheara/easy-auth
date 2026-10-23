//! Stateful native refresh/revocation from an explicit stored offline grant.
mod ports;
mod service;
#[cfg(test)]
mod tests;
mod tokens;

pub use ports::{
    IssuerNativeCredentialRequest, IssuerNativeRefreshData, IssuerNativeRefreshOutcome,
    IssuerNativeRefreshRepository, IssuerNativeRotationRequest,
};
pub use service::IssuerNativeRefresh;
pub use tokens::IssuerNativeRotatedTokens;
pub const ISSUER_NATIVE_ACCESS_LIFETIME_SECONDS: i64 = 300;
/// Bound retained replay history; exhaustion requires fresh explicit consent.
pub const MAX_ISSUER_NATIVE_REFRESH_GENERATION: i64 = 10_000;
