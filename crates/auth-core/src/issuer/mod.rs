//! Outbound issuer features, separate from inbound federation and local sessions.
mod authentication;
#[cfg(feature = "issuer-codes")]
mod codes;
mod native;
#[cfg(test)]
mod native_tests;
mod redirects;
mod registration;
#[cfg(test)]
mod tests;
#[cfg(feature = "issuer-token-management")]
mod tokens;

pub use authentication::IssuerClientAuthentication;
#[cfg(feature = "issuer-codes")]
pub use codes::{
    ISSUER_AUTHORIZATION_LIFETIME_SECONDS, ISSUER_CODE_LIFETIME_SECONDS,
    ISSUER_TOKEN_ATTEMPTS_PER_MINUTE, ISSUER_TOKEN_RATE_WINDOW_SECONDS, IssuerAuthority,
    IssuerAuthorization, IssuerAuthorizationDestination, IssuerAuthorizationInput,
    IssuerAuthorizationPreview, IssuerAuthorizationRepository, IssuerAuthorizationRequest,
    IssuerAuthorizationReturn, IssuerAuthorizationStart, IssuerCodeRedemption, IssuerConsentProof,
    IssuerGrantData, IssuerPkceVerifier, IssuerRedeemedCode, IssuerTokenError, IssuerTokenResult,
    MAX_ISSUER_PENDING_PER_OWNER, MAX_ISSUER_PENDING_PER_REALM, MAX_ISSUER_TOKEN_SOURCES_PER_REALM,
};
pub use redirects::{MAX_ISSUER_REDIRECT_BYTES, MAX_ISSUER_REDIRECTS};
pub use registration::{IssuerClientKind, IssuerClientRegistration, IssuerRedirectProfile};
#[cfg(feature = "issuer-token-management")]
pub use tokens::{
    IssuerAccessData, IssuerActiveAccess, IssuerPresentedToken, IssuerTokenManagement,
    IssuerTokenStatusRepository, IssuerTokenStatusRequest,
};
#[cfg(feature = "issuer-native-refresh")]
pub use tokens::{
    IssuerNativeRefreshPolicy, MAX_NATIVE_REFRESH_IDLE_SECONDS, MAX_NATIVE_REFRESH_LIFETIME_SECONDS,
};

#[cfg(feature = "issuer-signing")]
mod signing;
#[cfg(feature = "issuer-signing")]
pub use signing::{
    ISSUER_ID_TOKEN_LIFETIME_SECONDS, ISSUER_KEY_PROPAGATION_SECONDS, IssuerDiscoveryDocument,
    IssuerJwksDocument, IssuerKeyPublication, IssuerMetadata, IssuerMetadataRepository,
    IssuerPublicKey, IssuerSignedCode, IssuerSigningKey, IssuerSigningSnapshot, IssuerTokenIssuer,
    IssuerTokenPreparationData, IssuerTokenRepository, IssuerTokens, MAX_ISSUER_PUBLISHED_KEYS,
};

#[cfg(feature = "issuer-native-refresh")]
pub use tokens::{
    IssuerNativeAuthorization, IssuerNativeAuthorizationDestination,
    IssuerNativeAuthorizationInput, IssuerNativeAuthorizationPreparation,
    IssuerNativeAuthorizationPreview, IssuerNativeAuthorizationRepository,
    IssuerNativeAuthorizationRequest, IssuerNativeAuthorizationStart, IssuerNativeConsentData,
};

#[cfg(feature = "issuer-native-refresh")]
pub use signing::{
    IssuerNativeSignedCode, IssuerNativeTokenCommit, IssuerNativeTokenIssuer,
    IssuerNativeTokenPreparationData, IssuerNativeTokenRepository, IssuerNativeTokens,
    MAX_ISSUER_NATIVE_FAMILIES_PER_OWNER_CLIENT,
};

#[cfg(feature = "issuer-native-refresh")]
pub use tokens::{
    ISSUER_NATIVE_ACCESS_LIFETIME_SECONDS, IssuerNativeCredentialRequest, IssuerNativeRefresh,
    IssuerNativeRefreshData, IssuerNativeRefreshOutcome, IssuerNativeRefreshRepository,
    IssuerNativeRotatedTokens, IssuerNativeRotationRequest,
};

#[cfg(feature = "issuer-native-refresh")]
pub use tokens::MAX_ISSUER_NATIVE_REFRESH_GENERATION;
