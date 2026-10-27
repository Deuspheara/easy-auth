use auth_core::{
    Error, GoogleAccountDeletionAuthorization, GoogleAuthorization, GoogleSessionAgeCodeExchange,
    OAuthTransactions, OidcAccountDeletion, OidcIdentityPolicy, OidcSignIn, Result,
};
use std::sync::Arc;

/// Explicit eligible-client Google composition. No ordinary activation or provider
/// capability/freshness inference follows from construction.
#[derive(Clone)]
pub struct GoogleWebServices {
    pub(super) policy: OidcIdentityPolicy,
    pub(super) authorization: Arc<GoogleAuthorization>,
    pub(super) deletion_authorization: Arc<GoogleAccountDeletionAuthorization>,
    pub(super) sign_in: Arc<OidcSignIn>,
    pub(super) deletion: Arc<OidcAccountDeletion>,
}
impl GoogleWebServices {
    #[cfg(feature = "social-linking-web")]
    pub(in crate::oidc) fn policy(&self) -> &OidcIdentityPolicy {
        &self.policy
    }

    pub fn new(
        policy: OidcIdentityPolicy,
        transactions: Arc<OAuthTransactions>,
        exchange: Arc<GoogleSessionAgeCodeExchange>,
        sign_in: Arc<OidcSignIn>,
        deletion: Arc<OidcAccountDeletion>,
    ) -> Result<Self> {
        if policy.configuration() != exchange.configuration() {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            policy,
            authorization: Arc::new(GoogleAuthorization::new_session_age(
                transactions.clone(),
                exchange.clone(),
            )?),
            deletion_authorization: Arc::new(GoogleAccountDeletionAuthorization::new(
                transactions,
                exchange,
            )?),
            sign_in,
            deletion,
        })
    }
}
