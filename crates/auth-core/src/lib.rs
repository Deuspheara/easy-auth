//! Shared authentication use cases. HTTP and SQL implementations live outside this crate.
mod audit;
mod auth;
mod email;
mod error;
mod identity;
mod notifications;
#[cfg(feature = "oauth-transactions")]
mod oauth;
#[cfg(feature = "oidc-egress")]
mod oidc;
#[cfg(feature = "passkeys")]
mod passkeys;
mod password;
mod ports;
mod secret;
mod sessions;

pub use audit::AuditEvent;
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
