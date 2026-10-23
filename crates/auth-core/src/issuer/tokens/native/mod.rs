//! Explicit native offline configuration, separate from browser-session authority.
mod consent;
mod policy;
#[cfg(test)]
mod tests;

pub use consent::{
    IssuerNativeAuthorization, IssuerNativeAuthorizationDestination,
    IssuerNativeAuthorizationInput, IssuerNativeAuthorizationPreparation,
    IssuerNativeAuthorizationPreview, IssuerNativeAuthorizationRepository,
    IssuerNativeAuthorizationRequest, IssuerNativeAuthorizationStart, IssuerNativeConsentData,
};
pub use policy::{
    IssuerNativeRefreshPolicy, MAX_NATIVE_REFRESH_IDLE_SECONDS, MAX_NATIVE_REFRESH_LIFETIME_SECONDS,
};
