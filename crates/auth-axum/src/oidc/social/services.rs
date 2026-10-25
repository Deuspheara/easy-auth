use crate::oidc::{AppleWebServices, GoogleWebServices};
use auth_core::{
    AppleIdentityLinkAuthorization, Error, GoogleIdentityLinkAuthorization, OidcIdentityLinking,
    Result,
};
use std::sync::Arc;

/// Explicit experimental web composition. Real-provider acceptance and remote
/// grant revocation remain separate gates; construction enables neither.
#[derive(Clone)]
pub struct SocialWebServices {
    pub(super) google: GoogleWebServices,
    pub(super) apple: AppleWebServices,
    pub(super) google_link: Arc<GoogleIdentityLinkAuthorization>,
    pub(super) apple_link: Arc<AppleIdentityLinkAuthorization>,
    pub(super) linking: Arc<OidcIdentityLinking>,
}
impl SocialWebServices {
    pub fn new(
        google: GoogleWebServices,
        apple: AppleWebServices,
        google_link: Arc<GoogleIdentityLinkAuthorization>,
        apple_link: Arc<AppleIdentityLinkAuthorization>,
        linking: Arc<OidcIdentityLinking>,
    ) -> Result<Self> {
        if google.policy().configuration() != google_link.configuration()
            || apple.policy().configuration() != apple_link.configuration()
            || google_link.configuration().realm() != apple_link.configuration().realm()
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            google,
            apple,
            google_link,
            apple_link,
            linking,
        })
    }
}
