//! Outbound authorization-code policy; inbound provider proof types are separate.
mod authority;
mod data;
mod error;
mod pkce;
mod repository;
mod request;
mod response;
mod service;
#[cfg(test)]
mod tests;

pub use authority::IssuerAuthority;
pub use data::{
    IssuerAuthorizationDestination, IssuerAuthorizationReturn, IssuerAuthorizationStart,
    IssuerGrantData, IssuerRedeemedCode,
};
pub use error::{IssuerTokenError, IssuerTokenResult};
pub use pkce::IssuerPkceVerifier;
pub use repository::{IssuerAuthorizationRepository, IssuerCodeRedemption, IssuerConsentProof};
pub use request::{IssuerAuthorizationInput, IssuerAuthorizationRequest};
pub use service::IssuerAuthorization;

pub const ISSUER_AUTHORIZATION_LIFETIME_SECONDS: i64 = 300;
pub const ISSUER_CODE_LIFETIME_SECONDS: i64 = 60;
pub const MAX_ISSUER_PENDING_PER_OWNER: i64 = 3;
pub const MAX_ISSUER_PENDING_PER_REALM: i64 = 256;
pub const ISSUER_TOKEN_ATTEMPTS_PER_MINUTE: i64 = 30;
pub const ISSUER_TOKEN_RATE_WINDOW_SECONDS: i64 = 60;
pub const MAX_ISSUER_TOKEN_SOURCES_PER_REALM: i64 = 1024;
