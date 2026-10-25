use super::authorization::SignIn;
use auth_core::{
    AppleAuthorization, AppleClientType, AppleCodeExchange, Error, OAuthTransactions,
    OidcIdentityPolicy, OidcSignIn, Result,
};
use std::sync::Arc;

/// Experimental web-only composition; no registration or lifecycle is inferred.
#[derive(Clone)]
pub struct AppleWebServices {
    pub(super) policy: OidcIdentityPolicy,
    pub(super) operation: SignIn,
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
        validate(&policy, &exchange)?;
        Ok(Self {
            policy,
            operation: SignIn::Standard {
                authorization: Arc::new(AppleAuthorization::new(transactions, exchange)?),
                sign_in,
            },
        })
    }

    /// Explicit capture selection; repository configuration must supply the vault.
    /// Missing protection fails the final commit rather than discarding credentials.
    #[cfg(feature = "apple-grants-web")]
    pub fn new_with_grants(
        policy: OidcIdentityPolicy,
        transactions: Arc<OAuthTransactions>,
        exchange: Arc<AppleCodeExchange>,
        sign_in: Arc<auth_core::AppleGrantSignIn>,
    ) -> Result<Self> {
        validate(&policy, &exchange)?;
        Ok(Self {
            policy,
            operation: SignIn::Captured {
                authorization: Arc::new(auth_core::AppleGrantAuthorization::sign_in(
                    transactions,
                    exchange,
                )?),
                sign_in,
            },
        })
    }
}

fn validate(policy: &OidcIdentityPolicy, exchange: &AppleCodeExchange) -> Result<()> {
    if policy.configuration() != exchange.configuration()
        || exchange.client_type() != AppleClientType::Web
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
