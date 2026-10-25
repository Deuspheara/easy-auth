use super::{AppleClientType, AppleCodeExchange, EXCHANGE_TIMEOUT};
use crate::oidc::apple::grants::AppleVerifiedGrant;
use crate::{Error, OAuthExchange, OAuthPurpose, OidcAuthorizationCode, Result};

impl AppleCodeExchange {
    pub(in crate::oidc::apple) async fn capture_grant(
        &self,
        exchange: OAuthExchange,
        code: OidcAuthorizationCode,
    ) -> Result<AppleVerifiedGrant> {
        match exchange.purpose() {
            OAuthPurpose::SignIn => {}
            OAuthPurpose::Link { .. } if self.client_type == AppleClientType::Web => {}
            _ => return Err(Error::Unauthorized),
        }
        if exchange.configuration() != self.configuration()
            || exchange.redirect() != self.configuration().redirect()
        {
            return Err(Error::Unauthorized);
        }
        let lease = self.verifier.lease_operation()?;
        tokio::time::timeout(EXCHANGE_TIMEOUT, async {
            // Conservative start of redemption, not receipt time: slow I/O must
            // not extend an access token's stated lifetime. This is not freshness.
            let requested_us = self.repository.check_oidc_exchange(&exchange).await?;
            let (response, discovery) = self.redeem(&exchange, code).await?;
            let reply = response.apple_grant(requested_us)?;
            let identity = self
                .verifier
                .verify_leased(exchange, reply.id_token, lease, Some(discovery))
                .await?;
            AppleVerifiedGrant::captured(identity, reply.token, reply.access_expires_us)
        })
        .await
        .map_err(|_| Error::Unavailable)?
    }
}
