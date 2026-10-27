use super::{GoogleCodeExchange, GoogleSessionAgeCodeExchange};
use crate::{
    Error, OAuthConnection, OAuthExchange, OAuthPurpose, OAuthStart, OidcAuthorizationCode,
    OidcAuthorizationUrl, Result, VerifiedOidcIdentity,
};
use std::sync::Arc;

/// Trusted concrete profile selection, never inferred from callback/claim input.
pub(super) enum AuthorizationExchange {
    Ordinary(Arc<GoogleCodeExchange>),
    SessionAge(Arc<GoogleSessionAgeCodeExchange>),
    AccountDeletion(Arc<GoogleSessionAgeCodeExchange>),
    #[cfg(feature = "oidc-linking")]
    LinkOrdinary(Arc<GoogleCodeExchange>),
    #[cfg(feature = "oidc-linking")]
    LinkSessionAge(Arc<GoogleSessionAgeCodeExchange>),
}
impl AuthorizationExchange {
    pub fn configuration(&self) -> &OAuthConnection {
        match self {
            Self::Ordinary(value) => value.configuration(),
            Self::SessionAge(value) | Self::AccountDeletion(value) => value.configuration(),
            #[cfg(feature = "oidc-linking")]
            Self::LinkOrdinary(value) => value.configuration(),
            #[cfg(feature = "oidc-linking")]
            Self::LinkSessionAge(value) => value.configuration(),
        }
    }
    pub async fn authorization_url(
        &self,
        start: &OAuthStart,
        redirect: &str,
    ) -> Result<OidcAuthorizationUrl> {
        match self {
            Self::Ordinary(value) => value.authorization_for_return(start, redirect).await,
            Self::SessionAge(value) | Self::AccountDeletion(value) => {
                value.authorization_for_return(start, redirect).await
            }
            #[cfg(feature = "oidc-linking")]
            Self::LinkOrdinary(value) => value
                .authorization_for_return(start, redirect)
                .await?
                .with_google_account_selection(),
            #[cfg(feature = "oidc-linking")]
            Self::LinkSessionAge(value) => value
                .authorization_for_return(start, redirect)
                .await?
                .with_google_account_selection(),
        }
    }
    pub fn require_purpose(&self, purpose: &OAuthPurpose) -> Result<()> {
        match (self, purpose) {
            (Self::AccountDeletion(_), OAuthPurpose::DeleteProviderAccount { .. })
            | (Self::Ordinary(_) | Self::SessionAge(_), OAuthPurpose::SignIn) => Ok(()),
            #[cfg(feature = "oidc-linking")]
            (Self::LinkOrdinary(_) | Self::LinkSessionAge(_), OAuthPurpose::Link { .. }) => Ok(()),
            _ => Err(Error::Unauthorized),
        }
    }
    pub async fn exchange(
        &self,
        exchange: OAuthExchange,
        code: OidcAuthorizationCode,
    ) -> Result<VerifiedOidcIdentity> {
        match self {
            Self::Ordinary(value) => value.exchange(exchange, code).await,
            Self::SessionAge(value) => value.exchange(exchange, code).await,
            Self::AccountDeletion(value) => value.exchange_account_deletion(exchange, code).await,
            #[cfg(feature = "oidc-linking")]
            Self::LinkOrdinary(value) => value.exchange_linking(exchange, code).await,
            #[cfg(feature = "oidc-linking")]
            Self::LinkSessionAge(value) => value.exchange_linking(exchange, code).await,
        }
    }
}
