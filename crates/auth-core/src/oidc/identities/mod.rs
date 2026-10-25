mod deletion;
#[cfg(feature = "oidc-linking")]
mod linking;
mod mapped;
mod policy;
mod signin;
#[cfg(feature = "oidc-linking")]
pub use linking::{OidcIdentityLinkRepository, OidcIdentityLinking};

pub use deletion::{
    MAX_OIDC_DELETION_AUTH_AGE_SECONDS, OidcAccountDeletion, OidcAccountDeletionRepository,
};
pub use mapped::OidcMappedIdentity;
pub use policy::{OidcDisplayNameClaim, OidcIdentityPolicy, OidcJitPolicy};
pub use signin::{OidcIdentityRepository, OidcSignIn};

pub(crate) use crate::display_name::usable_display_name;
