use auth_core::{Error, OAuthTransactions, OidcCodeExchange, OidcIdentityPolicy, Result};
use std::sync::Arc;

/// One trusted exact source snapshot shared by OIDC browser operations.
pub(super) struct Source {
    pub policy: OidcIdentityPolicy,
    pub transactions: Arc<OAuthTransactions>,
    pub exchange: Arc<OidcCodeExchange>,
}
impl Source {
    pub fn new(
        policy: OidcIdentityPolicy,
        transactions: Arc<OAuthTransactions>,
        exchange: Arc<OidcCodeExchange>,
    ) -> Result<Self> {
        if policy.configuration() != transactions.configuration()
            || policy.configuration() != exchange.configuration()
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            policy,
            transactions,
            exchange,
        })
    }
}
