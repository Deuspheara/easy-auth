use super::{AppleClientType, AppleCodeExchange};
use crate::{
    Error, OAuthExchange, OidcAuthorizationCode, OidcDiscovery, OidcTokenRequest,
    OidcTokenResponse, Result,
};

impl AppleCodeExchange {
    pub(super) async fn redeem(
        &self,
        exchange: &OAuthExchange,
        code: OidcAuthorizationCode,
    ) -> Result<(OidcTokenResponse, OidcDiscovery)> {
        self.repository.check_oidc_exchange(exchange).await?;
        let discovery = self.discovery().await?;
        let url = url::Url::parse(discovery.token_endpoint()).map_err(|_| Error::Unavailable)?;
        let target = self.documents.resolve_target(url).await?;
        let now = self.repository.check_oidc_exchange(exchange).await?;
        let secret = self.signer.issue(now).await?;
        let expires_at = secret.expires_at();
        let current = self.repository.check_oidc_exchange(exchange).await?;
        if current < now || current < 0 || i128::from(current) >= i128::from(expires_at) * 1_000_000
        {
            return Err(Error::Unauthorized);
        }
        let redirect = (self.client_type == AppleClientType::Web).then_some(exchange.redirect());
        let request = OidcTokenRequest::apple(
            self.configuration().provider_client(),
            redirect,
            code,
            secret.into_client_authentication()?,
        )?;
        let response = self.http.post(&target, &request).await?;
        Ok((response, discovery))
    }
}
