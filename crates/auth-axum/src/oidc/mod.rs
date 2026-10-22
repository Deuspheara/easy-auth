mod cookies;
mod deletion;
#[cfg(feature = "google-web")]
mod google;
mod source;
#[cfg(feature = "oidc-web")]
mod web;

pub use deletion::{
    OidcAccountDeletionServices, experimental_oidc_account_deletion_router,
    oidc_account_deletion_openapi,
};
#[cfg(feature = "google-web")]
pub use google::{GoogleWebServices, experimental_google_web_router, google_web_openapi};
#[cfg(feature = "oidc-web")]
pub use web::{OidcWebServices, oidc_web_openapi, oidc_web_router};

#[cfg(all(feature = "oidc-web", feature = "saml-web"))]
pub(crate) use web::{attach, clear_proofs};
