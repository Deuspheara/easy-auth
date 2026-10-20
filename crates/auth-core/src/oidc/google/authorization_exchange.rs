use super::{GoogleCodeExchange, GoogleSessionAgeCodeExchange};
use crate::{
    OAuthConnection, OAuthExchange, OAuthStart, OidcAuthorizationCode, OidcAuthorizationUrl,
    Result, VerifiedOidcIdentity,
};
use std::sync::Arc;

/// Trusted concrete profile selection, never inferred from callback/claim input.
pub(super) enum AuthorizationExchange {
    Ordinary(Arc<GoogleCodeExchange>),
    SessionAge(Arc<GoogleSessionAgeCodeExchange>),
}
impl AuthorizationExchange {
    pub fn configuration(&self) -> &OAuthConnection {
        match self {
            Self::Ordinary(value) => value.configuration(),
            Self::SessionAge(value) => value.configuration(),
        }
    }
    pub async fn authorization_url(&self, start: &OAuthStart) -> Result<OidcAuthorizationUrl> {
        match self {
            Self::Ordinary(value) => value.authorization_url(start).await,
            Self::SessionAge(value) => value.authorization_url(start).await,
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
        }
    }
}
