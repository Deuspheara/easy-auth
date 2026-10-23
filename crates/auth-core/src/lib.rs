//! Shared authentication use cases. HTTP and SQL implementations live outside this crate.
mod audit;
mod auth;
#[cfg(any(feature = "oidc-identities", feature = "saml-identities"))]
mod display_name;
mod email;
mod error;
mod identity;
#[cfg(feature = "issuer-clients")]
mod issuer;
mod notifications;
#[cfg(feature = "oauth-transactions")]
mod oauth;
#[cfg(feature = "oidc-egress")]
mod oidc;
#[cfg(feature = "passkeys")]
mod passkeys;
mod password;
mod ports;
#[cfg(feature = "saml-requests")]
mod saml;
mod secret;
mod sessions;

pub use audit::{
    AuditEvent, IssuerNativeCredentialAction, IssuerNativeCredentialEvent,
    IssuerNativeCredentialKind,
};
pub use auth::Auth;
pub use email::normalize_email;
pub use error::{Error, Result};
pub use identity::{AuthenticationPolicy, User};
pub use notifications::{SecurityNotice, SecurityNoticeKind};
#[cfg(feature = "oauth-transactions")]
pub use oauth::{
    OAuthBrowserProof, OAuthCallback, OAuthConnection, OAuthExchange, OAuthIntent,
    OAuthMixupDefense, OAuthPurpose, OAuthRedirect, OAuthRedirectPolicy, OAuthRequest, OAuthStart,
    OAuthTransactionRepository, OAuthTransactions,
};
#[cfg(feature = "oidc-egress")]
pub use oidc::{
    MAX_OIDC_DNS_ANSWERS, MAX_OIDC_DOCUMENT_BYTES, OIDC_FETCH_TIMEOUT, OidcConnectionRepository,
    OidcDiscovery, OidcDocuments, OidcHttp, OidcHttpResponse, OidcJwksDocument, OidcTarget,
};
#[cfg(feature = "passkeys")]
pub use passkeys::{
    MAX_PASSKEYS_PER_ACCOUNT, PASSKEY_RECOVERY_DELAY_SECONDS, PASSKEY_RECOVERY_LIFETIME_SECONDS,
    PasskeyAuthenticationOptions, PasskeyAuthenticationRepository, PasskeyAuthenticationRequest,
    PasskeyAuthenticationResponse, PasskeyAuthenticationStart, PasskeyCreationOptions,
    PasskeyEnrollment, PasskeyEnrollmentContext, PasskeyEnrollmentOptions,
    PasskeyEnrollmentRequest, PasskeyEnrollmentStart, PasskeyInfo, PasskeyManagement,
    PasskeyManagementRepository, PasskeyManagementRequest, PasskeyRecoveryAssertion,
    PasskeyRecoveryClaimInfo, PasskeyRecoveryClaimRepository, PasskeyRecoveryClaimRequest,
    PasskeyRecoveryClaims, PasskeyRecoveryCodeCancellation, PasskeyRecoveryCreation,
    PasskeyRecoveryKeyCancellation, PasskeyRecoveryReplacement,
    PasskeyRecoveryReplacementRepository, PasskeyRecoveryReplacementRequest,
    PasskeyRecoveryReplacementStart, PasskeyRecoverySetup, PasskeyRecoverySetupRepository,
    PasskeyRecoverySetupRequest, PasskeyRecoveryTarget, PasskeyRegistrationResponse,
    PasskeyRepository, PasskeyService, PasskeySignIn, PasskeySignInOptions, PasskeySignup,
    PasskeySignupAssertion, PasskeySignupCreation, PasskeySignupRegistrationContext,
    PasskeySignupRepository, PasskeySignupRequest, PasskeySignupStart, PreparedPasskeyRecoveryCode,
    PrivatePasskeyAuthentication, PrivatePasskeyRegistration, StoredPasskey, VerifiedPasskey,
    VerifiedPasskeyAuthentication, VerifiedPasskeyRecoveryRegistration,
    VerifiedPasskeySignupRegistration, authorize_passkey_enrollment,
};
pub use password::{Password, PasswordService};
pub use ports::{EmailDelivery, Repository};
#[cfg(feature = "saml-requests")]
pub use saml::{
    MAX_SAML_PENDING_PER_CONNECTION, SAML_REQUEST_LIFETIME_SECONDS, SamlBrowserProof,
    SamlPreparedResponse, SamlRegistration, SamlRequestAdmission, SamlRequestRepository,
    SamlRequestTiming, SamlStart, SamlTransactions,
};
#[cfg(feature = "saml-certificates")]
pub use saml::{MAX_SAML_PINNED_CERTIFICATES, SamlCertificateTrust, SamlPinnedCertificate};
#[cfg(feature = "saml-verification")]
pub use saml::{
    SamlAttribute, SamlPostResponse, SamlReplayKind, SamlReplayRecord, SamlResponseVerifier,
    SamlVerificationMaterial, SamlVerificationRepository, VerifiedSamlAssertion,
};
#[cfg(feature = "saml-identities")]
pub use saml::{
    SamlIdentityPolicy, SamlIdentityRepository, SamlJitPolicy, SamlMappedIdentity, SamlSignIn,
};
pub use secret::{Secret, Verifier};
pub use sessions::{SessionInfo, SessionPage};

#[cfg(feature = "google")]
pub use oidc::{
    GoogleAccountDeletionAuthorization, GoogleAuthorization, GoogleAuthorizationCompletion,
    GoogleAuthorizationOutcome, GoogleAuthorizationResponse, GoogleAuthorizationStart,
    GoogleCodeExchange, GoogleSessionAgeCodeExchange,
};

#[cfg(feature = "oidc-identities")]
pub use oidc::{
    MAX_OIDC_DELETION_AUTH_AGE_SECONDS, OidcAccountDeletion, OidcAccountDeletionRepository,
    OidcDisplayNameClaim, OidcIdentityPolicy, OidcIdentityRepository, OidcJitPolicy,
    OidcMappedIdentity, OidcSignIn,
};

#[cfg(feature = "oidc-verification")]
pub use oidc::{
    OidcAuthorizationCode, OidcAuthorizationUrl, OidcClientAuthentication, OidcClientSecret,
    OidcCodeExchange, OidcExchangeRepository, OidcIdToken, OidcSigningAlgorithm, OidcTokenHttp,
    OidcTokenRequest, OidcTokenResponse, OidcTokenVerifier, OidcVerificationPolicy,
    VerifiedOidcIdentity,
};

#[cfg(feature = "saml-identities")]
pub use saml::{
    MAX_SAML_DELETION_AUTH_AGE_SECONDS, SamlAccountDeletion, SamlAccountDeletionRepository,
    SamlDeletionBinding, SamlDeletionRequestContext, SamlDeletionRequestRepository,
    SamlDeletionRequests, SamlDeletionVerifier, SamlPreparedDeletion, SamlVerifiedDeletion,
};

#[cfg(feature = "issuer-codes")]
pub use issuer::{
    ISSUER_AUTHORIZATION_LIFETIME_SECONDS, ISSUER_CODE_LIFETIME_SECONDS,
    ISSUER_TOKEN_ATTEMPTS_PER_MINUTE, ISSUER_TOKEN_RATE_WINDOW_SECONDS, IssuerAuthority,
    IssuerAuthorization, IssuerAuthorizationDestination, IssuerAuthorizationInput,
    IssuerAuthorizationPreview, IssuerAuthorizationRepository, IssuerAuthorizationRequest,
    IssuerAuthorizationReturn, IssuerAuthorizationStart, IssuerCodeRedemption, IssuerConsentProof,
    IssuerGrantData, IssuerPkceVerifier, IssuerRedeemedCode, IssuerTokenError, IssuerTokenResult,
    MAX_ISSUER_PENDING_PER_OWNER, MAX_ISSUER_PENDING_PER_REALM, MAX_ISSUER_TOKEN_SOURCES_PER_REALM,
};
#[cfg(feature = "issuer-clients")]
pub use issuer::{
    IssuerClientAuthentication, IssuerClientKind, IssuerClientRegistration, IssuerRedirectProfile,
    MAX_ISSUER_REDIRECT_BYTES, MAX_ISSUER_REDIRECTS,
};

#[cfg(feature = "issuer-token-management")]
pub use issuer::{
    IssuerAccessData, IssuerActiveAccess, IssuerPresentedToken, IssuerTokenManagement,
    IssuerTokenStatusRepository, IssuerTokenStatusRequest,
};

#[cfg(feature = "issuer-native-refresh")]
pub use issuer::{
    ISSUER_NATIVE_SCOPE, IssuerNativeRefreshPolicy, MAX_NATIVE_REFRESH_IDLE_SECONDS,
    MAX_NATIVE_REFRESH_LIFETIME_SECONDS,
};

#[cfg(feature = "issuer-signing")]
pub use issuer::{
    ISSUER_ID_TOKEN_LIFETIME_SECONDS, ISSUER_KEY_PROPAGATION_SECONDS, IssuerDiscoveryDocument,
    IssuerJwksDocument, IssuerKeyPublication, IssuerMetadata, IssuerMetadataRepository,
    IssuerPublicKey, IssuerSignedCode, IssuerSigningKey, IssuerSigningSnapshot, IssuerTokenIssuer,
    IssuerTokenPreparationData, IssuerTokenRepository, IssuerTokens, MAX_ISSUER_PUBLISHED_KEYS,
};

#[cfg(feature = "issuer-native-refresh")]
pub use issuer::{
    IssuerNativeAuthorization, IssuerNativeAuthorizationDestination,
    IssuerNativeAuthorizationInput, IssuerNativeAuthorizationPreparation,
    IssuerNativeAuthorizationPreview, IssuerNativeAuthorizationRepository,
    IssuerNativeAuthorizationRequest, IssuerNativeAuthorizationStart, IssuerNativeConsentData,
};

#[cfg(feature = "issuer-native-refresh")]
pub use issuer::{
    IssuerClientTokens, IssuerNativeSignedCode, IssuerNativeTokenCommit, IssuerNativeTokenIssuer,
    IssuerNativeTokenPreparationData, IssuerNativeTokenRepository, IssuerNativeTokens,
    MAX_ISSUER_NATIVE_FAMILIES_PER_OWNER_CLIENT,
};

#[cfg(feature = "issuer-native-refresh")]
pub use issuer::{
    ISSUER_NATIVE_ACCESS_LIFETIME_SECONDS, IssuerNativeCredentialRequest, IssuerNativeRefresh,
    IssuerNativeRefreshData, IssuerNativeRefreshOutcome, IssuerNativeRefreshRepository,
    IssuerNativeRotatedTokens, IssuerNativeRotationRequest,
};

#[cfg(feature = "issuer-native-refresh")]
pub use issuer::MAX_ISSUER_NATIVE_REFRESH_GENERATION;
