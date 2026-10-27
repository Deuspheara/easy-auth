use super::{
    GoogleAuthorization, GoogleAuthorizationCompletion, GoogleAuthorizationResponse,
    GoogleAuthorizationStart, GoogleCodeExchange, GoogleSessionAgeCodeExchange,
    authorization_exchange::AuthorizationExchange,
};
use crate::{
    Error, OAuthBrowserProof, OAuthConnection, OAuthIntent, OAuthRedirectPolicy, OAuthTransactions,
    Result, Secret,
};
use std::sync::Arc;

/// Explicit exact-web link proof, separate from ordinary sign-in and deletion.
/// Neither account selection nor verified output changes local ownership alone.
pub struct GoogleIdentityLinkAuthorization {
    operation: GoogleAuthorization,
}
impl GoogleIdentityLinkAuthorization {
    pub fn new(
        transactions: Arc<OAuthTransactions>,
        exchange: Arc<GoogleCodeExchange>,
    ) -> Result<Self> {
        Self::configured(transactions, AuthorizationExchange::LinkOrdinary(exchange))
    }
    pub fn new_session_age(
        transactions: Arc<OAuthTransactions>,
        exchange: Arc<GoogleSessionAgeCodeExchange>,
    ) -> Result<Self> {
        Self::configured(
            transactions,
            AuthorizationExchange::LinkSessionAge(exchange),
        )
    }
    fn configured(
        transactions: Arc<OAuthTransactions>,
        exchange: AuthorizationExchange,
    ) -> Result<Self> {
        if transactions.configuration().redirect_policy() != OAuthRedirectPolicy::Exact {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            operation: GoogleAuthorization::configured(transactions, exchange)?,
        })
    }
    pub fn configuration(&self) -> &OAuthConnection {
        self.operation.configuration()
    }
    pub async fn begin(&self, intent: &OAuthIntent<'_>) -> Result<GoogleAuthorizationStart> {
        self.operation.begin(intent).await
    }
    pub async fn finish(
        &self,
        intent: &OAuthIntent<'_>,
        expected_state: &Secret,
        proof: OAuthBrowserProof,
        actual_redirect: &str,
        response: GoogleAuthorizationResponse,
    ) -> Result<GoogleAuthorizationCompletion> {
        self.operation
            .finish(intent, expected_state, proof, actual_redirect, response)
            .await
    }
    pub async fn cancel(
        &self,
        intent: &OAuthIntent<'_>,
        state: &Secret,
        proof: &OAuthBrowserProof,
    ) -> Result<()> {
        self.operation.cancel(intent, state, proof).await
    }
}
