use super::apple_authorization::AppleLink;
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
    pub(super) apple_link: AppleLink,
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
        validate(&google, &apple, &google_link, apple_link.configuration())?;
        Ok(Self {
            google,
            apple,
            google_link,
            apple_link: AppleLink::Standard(apple_link),
            linking,
        })
    }

    /// Explicit captured Apple linking; Google and local unlink retain their
    /// existing concrete services and current-owner policy.
    #[cfg(feature = "apple-grants-web")]
    pub fn new_with_apple_grants(
        google: GoogleWebServices,
        apple: AppleWebServices,
        google_link: Arc<GoogleIdentityLinkAuthorization>,
        transactions: Arc<auth_core::OAuthTransactions>,
        exchange: Arc<auth_core::AppleCodeExchange>,
        apple_linking: Arc<auth_core::AppleGrantLinking>,
        linking: Arc<OidcIdentityLinking>,
    ) -> Result<Self> {
        let authorization = Arc::new(auth_core::AppleGrantAuthorization::linking(
            transactions,
            exchange,
        )?);
        validate(&google, &apple, &google_link, authorization.configuration())?;
        Ok(Self {
            google,
            apple,
            google_link,
            linking,
            apple_link: AppleLink::Captured {
                authorization,
                linking: apple_linking,
            },
        })
    }
}

fn validate(
    google: &GoogleWebServices,
    apple: &AppleWebServices,
    google_link: &GoogleIdentityLinkAuthorization,
    apple_link: &auth_core::OAuthConnection,
) -> Result<()> {
    if google.policy().configuration() != google_link.configuration()
        || apple.policy().configuration() != apple_link
        || google_link.configuration().realm() != apple_link.realm()
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
