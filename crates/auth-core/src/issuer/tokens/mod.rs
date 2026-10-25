//! Stateful token lifetime operations; none grants a local session or app role.
mod access;
#[cfg(feature = "issuer-native-refresh")]
mod native;
mod ports;
mod presented;
mod service;
#[cfg(test)]
mod tests;

pub use access::{IssuerAccessData, IssuerActiveAccess};
#[cfg(feature = "issuer-native-refresh")]
pub use native::{
    ISSUER_NATIVE_SCOPE, IssuerNativeRefreshPolicy, MAX_NATIVE_REFRESH_IDLE_SECONDS,
    MAX_NATIVE_REFRESH_LIFETIME_SECONDS,
};
pub use ports::{IssuerTokenStatusRepository, IssuerTokenStatusRequest};
pub use presented::IssuerPresentedToken;
pub use service::IssuerTokenManagement;

#[cfg(feature = "issuer-native-refresh")]
pub use native::{
    IssuerNativeAuthorization, IssuerNativeAuthorizationDestination,
    IssuerNativeAuthorizationInput, IssuerNativeAuthorizationPreparation,
    IssuerNativeAuthorizationPreview, IssuerNativeAuthorizationRepository,
    IssuerNativeAuthorizationRequest, IssuerNativeAuthorizationStart, IssuerNativeConsentData,
};

#[cfg(feature = "issuer-native-refresh")]
pub use native::{
    ISSUER_NATIVE_ACCESS_LIFETIME_SECONDS, IssuerNativeCredentialRequest, IssuerNativeRefresh,
    IssuerNativeRefreshData, IssuerNativeRefreshOutcome, IssuerNativeRefreshRepository,
    IssuerNativeRotatedTokens, IssuerNativeRotationRequest,
};

#[cfg(feature = "issuer-native-refresh")]
pub use native::MAX_ISSUER_NATIVE_REFRESH_GENERATION;

#[cfg(feature = "issuer-native-refresh")]
pub use native::{
    IssuerNativeAccessData, IssuerNativeActiveAccess, IssuerNativeConsumerPolicy,
    IssuerNativeIntrospection, IssuerNativeIntrospectionRepository,
};
