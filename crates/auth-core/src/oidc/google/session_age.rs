use super::exchange::IDENTITY_SCOPES;
use crate::{
    Error, OAuthConnection, OAuthExchange, OAuthPurpose, OAuthStart, OidcAuthorizationCode,
    OidcAuthorizationUrl, OidcCodeExchange, Result, VerifiedOidcIdentity,
};

/// Explicit opt-in for eligible registered Google applications with session-age
/// claims enabled. A request is neither feature eligibility nor fresh authentication.
/// Ordinary activation still requires supported, genuinely usable lifecycle evidence.
pub struct GoogleSessionAgeCodeExchange {
    exchange: OidcCodeExchange,
}
impl GoogleSessionAgeCodeExchange {
    pub(super) fn new(exchange: OidcCodeExchange) -> Self {
        Self { exchange }
    }

    pub fn configuration(&self) -> &OAuthConnection {
        self.exchange.configuration()
    }

    /// Fixed essential auth_time only. No unsupported reauthentication prompt,
    /// caller-selected claims, new trust or inference of a recent Google event.
    pub async fn authorization_url(&self, start: &OAuthStart) -> Result<OidcAuthorizationUrl> {
        self.exchange
            .authorization_url(start, IDENTITY_SCOPES)
            .await?
            .with_google_session_age()
    }

    pub async fn exchange(
        &self,
        exchange: OAuthExchange,
        code: OidcAuthorizationCode,
    ) -> Result<VerifiedOidcIdentity> {
        if !matches!(exchange.purpose(), OAuthPurpose::SignIn) {
            return Err(Error::Unauthorized);
        }
        self.verify(exchange, code).await
    }

    /// Provider proof only; deliberate confirmation and the original owner/source/
    /// subject/session, genuine freshness and final database caps remain mandatory.
    /// No registration, sign-in or linking proof can enter this path.
    pub async fn exchange_account_deletion(
        &self,
        exchange: OAuthExchange,
        code: OidcAuthorizationCode,
    ) -> Result<VerifiedOidcIdentity> {
        if !matches!(
            exchange.purpose(),
            OAuthPurpose::DeleteProviderAccount { .. }
        ) {
            return Err(Error::Unauthorized);
        }
        self.verify(exchange, code).await
    }

    async fn verify(
        &self,
        exchange: OAuthExchange,
        code: OidcAuthorizationCode,
    ) -> Result<VerifiedOidcIdentity> {
        let identity = self.exchange.exchange(exchange, code).await?;
        if identity.authenticated_at().is_none() {
            // A valid signed response without the explicitly selected capability
            // indicates unavailable provider-profile support, not a weak fallback.
            return Err(Error::Unavailable);
        }
        Ok(identity)
    }
}
