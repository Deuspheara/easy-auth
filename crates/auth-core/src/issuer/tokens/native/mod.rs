//! Explicit native offline configuration, separate from browser-session authority.
mod consent;
mod consumer;
mod family;
mod policy;
#[cfg(test)]
mod tests;

pub use consent::{
    IssuerNativeAuthorization, IssuerNativeAuthorizationDestination,
    IssuerNativeAuthorizationInput, IssuerNativeAuthorizationPreparation,
    IssuerNativeAuthorizationPreview, IssuerNativeAuthorizationRepository,
    IssuerNativeAuthorizationRequest, IssuerNativeAuthorizationStart, IssuerNativeConsentData,
};
pub use family::{
    ISSUER_NATIVE_ACCESS_LIFETIME_SECONDS, IssuerNativeCredentialRequest, IssuerNativeRefresh,
    IssuerNativeRefreshData, IssuerNativeRefreshOutcome, IssuerNativeRefreshRepository,
    IssuerNativeRotatedTokens, IssuerNativeRotationRequest,
};
pub use policy::{
    ISSUER_NATIVE_SCOPE, IssuerNativeRefreshPolicy, MAX_NATIVE_REFRESH_IDLE_SECONDS,
    MAX_NATIVE_REFRESH_LIFETIME_SECONDS,
};

#[cfg(feature = "issuer-native-refresh")]
pub use family::MAX_ISSUER_NATIVE_REFRESH_GENERATION;

pub use consumer::{
    IssuerNativeAccessData, IssuerNativeActiveAccess, IssuerNativeConsumerPolicy,
    IssuerNativeIntrospection, IssuerNativeIntrospectionRepository,
};
