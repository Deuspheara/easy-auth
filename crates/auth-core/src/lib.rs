//! Shared authentication use cases. HTTP and SQL implementations live outside this crate.
mod audit;
mod auth;
mod email;
mod error;
mod identity;
mod notifications;
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
#[cfg(feature = "passkeys")]
pub use passkeys::{
    MAX_PASSKEYS_PER_ACCOUNT, PasskeyAuthenticationOptions, PasskeyAuthenticationRepository,
    PasskeyAuthenticationRequest, PasskeyAuthenticationResponse, PasskeyAuthenticationStart,
    PasskeyCreationOptions, PasskeyEnrollment, PasskeyEnrollmentContext, PasskeyEnrollmentOptions,
    PasskeyEnrollmentRequest, PasskeyEnrollmentStart, PasskeyInfo, PasskeyManagement,
    PasskeyManagementRepository, PasskeyManagementRequest, PasskeyRegistrationResponse,
    PasskeyRepository, PasskeyService, PasskeySignIn, PasskeySignInOptions, PasskeySignup,
    PasskeySignupAssertion, PasskeySignupCreation, PasskeySignupRegistrationContext,
    PasskeySignupRepository, PasskeySignupRequest, PasskeySignupStart,
    PrivatePasskeyAuthentication, PrivatePasskeyRegistration, StoredPasskey, VerifiedPasskey,
    VerifiedPasskeyAuthentication, VerifiedPasskeySignupRegistration, authorize_passkey_enrollment,
};
pub use password::{Password, PasswordService};
pub use ports::{EmailDelivery, Repository};
pub use secret::{Secret, Verifier};
pub use sessions::{SessionInfo, SessionPage};
