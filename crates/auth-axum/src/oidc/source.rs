use auth_core::{Error, OAuthTransactions, OidcCodeExchange, OidcIdentityPolicy, Result};
use std::sync::Arc;

/// One trusted exact source snapshot shared by OIDC browser operations.
pub(super) struct Source {
    pub policy: OidcIdentityPolicy,
    pub transactions: Arc<OAuthTransactions>,
    pub exchange: Arc<OidcCodeExchange>,
}
impl Source {
    #[cfg(feature = "oidc-web")]
    pub fn sign_in_scopes(&self) -> &'static [&'static str] {
        match self.policy.display_name_claim() {
            auth_core::OidcDisplayNameClaim::Subject => &[],
            auth_core::OidcDisplayNameClaim::Name
            | auth_core::OidcDisplayNameClaim::PreferredUsername => &["profile"],
        }
    }
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
