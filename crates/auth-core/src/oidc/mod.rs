mod documents;
#[cfg(feature = "oidc-identities")]
mod identities;
mod metadata;
mod policy;
mod ports;
mod public_address;
#[cfg(feature = "oidc-identities")]
pub use identities::{OidcDisplayNameClaim, OidcIdentityPolicy, OidcJitPolicy, OidcMappedIdentity};
#[cfg(test)]
mod tests;

pub use documents::OidcDocuments;
pub use metadata::{OidcDiscovery, OidcJwksDocument};
pub use policy::{MAX_OIDC_DNS_ANSWERS, OidcTarget};
pub use ports::{
    MAX_OIDC_DOCUMENT_BYTES, OIDC_FETCH_TIMEOUT, OidcConnectionRepository, OidcHttp,
    OidcHttpResponse,
};

#[cfg(feature = "oidc-verification")]
mod verification;
#[cfg(feature = "oidc-verification")]
pub use verification::{
    OidcAuthorizationCode, OidcAuthorizationUrl, OidcClientAuthentication, OidcClientSecret,
    OidcCodeExchange, OidcExchangeRepository, OidcIdToken, OidcSigningAlgorithm, OidcTokenHttp,
    OidcTokenRequest, OidcTokenResponse, OidcTokenVerifier, OidcVerificationPolicy,
    VerifiedOidcIdentity,
};
