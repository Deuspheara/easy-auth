//! Same-origin browser transport, shared by embedding and the standalone service.
mod browser;
mod contract;
mod error;
#[cfg(all(feature = "oidc-web", feature = "saml-web"))]
mod federation;
#[cfg(all(feature = "oidc-web", feature = "saml-web"))]
pub use federation::experimental_oidc_saml_web_router;
mod handlers;
#[cfg(feature = "oidc-account-deletion")]
mod oidc;
#[cfg(feature = "passkey-enrollment")]
mod passkeys;
mod router;
#[cfg(feature = "saml-web")]
mod saml;

use auth_core::Auth;
pub use browser::BrowserConfig;
pub use contract::openapi;
pub use handlers::sessions::authenticate;
#[cfg(feature = "google-web")]
pub use oidc::{GoogleWebServices, experimental_google_web_router, google_web_openapi};
#[cfg(feature = "oidc-account-deletion")]
pub use oidc::{
    OidcAccountDeletionServices, experimental_oidc_account_deletion_router,
    oidc_account_deletion_openapi,
};
#[cfg(feature = "oidc-web")]
pub use oidc::{OidcWebServices, oidc_web_openapi, oidc_web_router};
#[cfg(feature = "passkey-enrollment")]
pub use passkeys::{experimental_passkey_enrollment_router, passkey_enrollment_openapi};
#[cfg(feature = "passkey-authentication")]
pub use passkeys::{experimental_passkey_router, passkey_authentication_openapi};
#[cfg(feature = "passkey-signup")]
pub use passkeys::{experimental_passkey_signup_router, passkey_signup_openapi};
pub use router::router;
#[cfg(feature = "saml-web")]
pub use saml::{
    SamlAccountDeletionWebServices, SamlWebServices, experimental_saml_web_router,
    saml_account_deletion_web_openapi, saml_web_openapi,
};

#[cfg(feature = "passkey-management")]
pub use passkeys::{experimental_passkey_management_router, passkey_management_openapi};

#[cfg(feature = "passkey-recovery-setup")]
pub use passkeys::{experimental_passkey_recovery_setup_router, passkey_recovery_setup_openapi};

#[cfg(feature = "passkey-recovery")]
pub use passkeys::{
    PasskeyRecoveryServices, experimental_passkey_recovery_router, passkey_recovery_openapi,
};
