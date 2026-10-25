use auth_core::{
    AppleAuthorization, AppleClientType, AppleCodeExchange, Error, OAuthTransactions,
    OidcIdentityPolicy, OidcSignIn, Result,
};
use std::sync::Arc;

/// Experimental web-only composition; no registration or lifecycle is inferred.
#[derive(Clone)]
pub struct AppleWebServices {
    pub(super) policy: OidcIdentityPolicy,
    pub(super) authorization: Arc<AppleAuthorization>,
    pub(super) sign_in: Arc<OidcSignIn>,
}
impl AppleWebServices {
    #[cfg(feature = "social-linking-web")]
    pub(in crate::oidc) fn policy(&self) -> &OidcIdentityPolicy {
        &self.policy
    }

    pub fn new(
        policy: OidcIdentityPolicy,
        transactions: Arc<OAuthTransactions>,
        exchange: Arc<AppleCodeExchange>,
        sign_in: Arc<OidcSignIn>,
    ) -> Result<Self> {
        if policy.configuration() != exchange.configuration()
            || exchange.client_type() != AppleClientType::Web
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            policy,
            authorization: Arc::new(AppleAuthorization::new(transactions, exchange)?),
            sign_in,
        })
    }
}
