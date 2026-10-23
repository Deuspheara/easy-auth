//! Outbound issuer configuration only; no token, consent or authentication grant.
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

pub use authentication::IssuerClientAuthentication;
#[cfg(feature = "issuer-codes")]
pub use codes::{
    ISSUER_AUTHORIZATION_LIFETIME_SECONDS, ISSUER_CODE_LIFETIME_SECONDS,
    ISSUER_TOKEN_ATTEMPTS_PER_MINUTE, ISSUER_TOKEN_RATE_WINDOW_SECONDS, IssuerAuthority,
    IssuerAuthorization, IssuerAuthorizationDestination, IssuerAuthorizationInput,
    IssuerAuthorizationRepository, IssuerAuthorizationRequest, IssuerAuthorizationReturn,
    IssuerAuthorizationStart, IssuerCodeRedemption, IssuerConsentProof, IssuerGrantData,
    IssuerPkceVerifier, IssuerRedeemedCode, IssuerTokenError, IssuerTokenResult,
    MAX_ISSUER_PENDING_PER_OWNER, MAX_ISSUER_PENDING_PER_REALM, MAX_ISSUER_TOKEN_SOURCES_PER_REALM,
};
pub use redirects::{MAX_ISSUER_REDIRECT_BYTES, MAX_ISSUER_REDIRECTS};
pub use registration::{IssuerClientKind, IssuerClientRegistration, IssuerRedirectProfile};
