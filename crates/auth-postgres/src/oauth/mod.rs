mod admission;
mod configuration;
#[cfg(feature = "oidc-identities")]
mod identities;
#[cfg(feature = "oidc-identities")]
mod identity_policy;
#[cfg(feature = "oidc-identities")]
mod identity_startup;
#[cfg(feature = "oidc-identities")]
pub(crate) use identity_policy::lock as lock_identity_policy;
mod ownership;
mod transactions;
#[cfg(feature = "oidc-verification")]
mod verification;

use crate::Postgres;
use async_trait::async_trait;
use auth_core::{OAuthRequest, OAuthTransactionRepository, Result};

#[async_trait]
impl OAuthTransactionRepository for Postgres {
    async fn save_oauth(&self, request: &OAuthRequest) -> Result<i64> {
        transactions::save(&self.pool, request, request.configuration.redirect()).await
    }
    async fn consume_oauth(&self, request: &OAuthRequest) -> Result<i64> {
        transactions::take(&self.pool, request, request.configuration.redirect()).await
    }
    async fn cancel_oauth(&self, request: &OAuthRequest) -> Result<()> {
        transactions::take(&self.pool, request, request.configuration.redirect())
            .await
            .map(|_| ())
    }
    async fn save_oauth_return(&self, request: &OAuthRequest, redirect: &str) -> Result<i64> {
        transactions::save(&self.pool, request, redirect).await
    }
    async fn consume_oauth_return(&self, request: &OAuthRequest, redirect: &str) -> Result<i64> {
        transactions::take(&self.pool, request, redirect).await
    }
    async fn cancel_oauth_return(&self, request: &OAuthRequest, redirect: &str) -> Result<()> {
        transactions::take(&self.pool, request, redirect)
            .await
            .map(|_| ())
    }
}

#[cfg(feature = "oidc-egress")]
#[async_trait]
impl auth_core::OidcConnectionRepository for Postgres {
    async fn check_oidc_connection(&self, connection: &auth_core::OAuthConnection) -> Result<()> {
        configuration::check(&self.pool, connection).await
    }
}

#[cfg(feature = "oidc-verification")]
#[async_trait]
impl auth_core::OidcExchangeRepository for Postgres {
    async fn check_oidc_exchange(&self, exchange: &auth_core::OAuthExchange) -> Result<i64> {
        verification::check(&self.pool, exchange).await
    }
}
