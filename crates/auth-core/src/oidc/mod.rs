#[cfg(feature = "apple")]
mod apple;
mod documents;
#[cfg(feature = "apple")]
pub use apple::{
    AppleAuthorization, AppleAuthorizationCompletion, AppleAuthorizationOutcome,
    AppleAuthorizationRequest, AppleAuthorizationResponse, AppleAuthorizationStart,
    AppleClientSecret, AppleClientSecretSigner, AppleClientType, AppleCodeExchange,
    AppleInitialProfile, AppleNonceEncoding,
};
#[cfg(feature = "google")]
mod google;
#[cfg(feature = "google")]
pub use google::{
    GoogleAccountDeletionAuthorization, GoogleAuthorization, GoogleAuthorizationCompletion,
    GoogleAuthorizationOutcome, GoogleAuthorizationResponse, GoogleAuthorizationStart,
    GoogleCodeExchange, GoogleSessionAgeCodeExchange,
};
#[cfg(feature = "oidc-identities")]
mod identities;
#[cfg(all(feature = "apple", feature = "oidc-linking"))]
pub use apple::AppleIdentityLinkAuthorization;
#[cfg(all(feature = "google", feature = "oidc-linking"))]
pub use google::GoogleIdentityLinkAuthorization;
#[cfg(feature = "oidc-linking")]
pub use identities::{OidcIdentityLinkRepository, OidcIdentityLinking};
mod metadata;
mod policy;
mod ports;
mod public_address;
#[cfg(feature = "oidc-identities")]
pub use identities::{
    MAX_OIDC_DELETION_AUTH_AGE_SECONDS, OidcAccountDeletion, OidcAccountDeletionRepository,
    OidcDisplayNameClaim, OidcIdentityPolicy, OidcIdentityRepository, OidcJitPolicy,
    OidcMappedIdentity, OidcSignIn,
};
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

#[cfg(feature = "oidc-client")]
pub use verification::{
    OidcClient, OidcClientAuthorization, OidcClientConfiguration, OidcClientError, OidcClientResult,
};

#[cfg(feature = "oidc-client")]
pub use verification::{
    OidcClientCredential, OidcClientCredentials, OidcClientIdentity, OidcClientTokens,
};
