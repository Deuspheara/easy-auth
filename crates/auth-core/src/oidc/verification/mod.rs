mod claim_flags;
mod claims;
mod exchange;
mod flow;
mod input;
mod keys;
mod policy;
#[cfg(feature = "oidc-identities")]
mod profile;
mod repository;
#[cfg(test)]
mod tests;
mod verified;
mod work;

pub use flow::OidcTokenVerifier;
pub use input::OidcIdToken;
pub use policy::{OidcSigningAlgorithm, OidcVerificationPolicy};
pub use repository::OidcExchangeRepository;
pub use verified::VerifiedOidcIdentity;

pub use exchange::{
    OidcAuthorizationCode, OidcAuthorizationUrl, OidcClientAuthentication, OidcClientSecret,
    OidcCodeExchange, OidcTokenHttp, OidcTokenRequest, OidcTokenResponse,
};

#[cfg(feature = "oidc-client")]
mod client;
#[cfg(feature = "oidc-client")]
pub use client::{
    OidcClient, OidcClientAuthorization, OidcClientConfiguration, OidcClientError, OidcClientResult,
};

#[cfg(feature = "oidc-client")]
pub use client::{
    OidcClientCredential, OidcClientCredentials, OidcClientIdentity, OidcClientTokens,
};
