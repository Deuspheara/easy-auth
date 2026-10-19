use crate::{OAuthExchange, Result};
use async_trait::async_trait;

#[async_trait]
pub trait OidcExchangeRepository: Send + Sync {
    /// Recheck the enabled exact configuration, original deadline and original
    /// linking owner/session under locks, then commit before any network I/O.
    /// Return database wall time in Unix microseconds from the final clock check.
    /// This read creates no identity/session and is not final commit authority.
    async fn check_oidc_exchange(&self, exchange: &OAuthExchange) -> Result<i64>;
}
