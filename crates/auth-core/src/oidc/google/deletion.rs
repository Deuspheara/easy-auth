use super::{
    GoogleAuthorization, GoogleAuthorizationCompletion, GoogleAuthorizationResponse,
    GoogleAuthorizationStart, GoogleSessionAgeCodeExchange,
    authorization_exchange::AuthorizationExchange,
};
use crate::{OAuthBrowserProof, OAuthConnection, OAuthIntent, OAuthTransactions, Result, Secret};
use std::sync::Arc;

/// Bound account-deletion authorization using the explicit eligible-client profile.
/// This service never erases an account or issues a session. Verified proof still
/// requires deliberate confirmation and current-policy mapping into OidcAccountDeletion.
pub struct GoogleAccountDeletionAuthorization {
    operation: GoogleAuthorization,
}
impl GoogleAccountDeletionAuthorization {
    pub fn new(
        transactions: Arc<OAuthTransactions>,
        exchange: Arc<GoogleSessionAgeCodeExchange>,
    ) -> Result<Self> {
        Ok(Self {
            operation: GoogleAuthorization::configured(
                transactions,
                AuthorizationExchange::AccountDeletion(exchange),
            )?,
        })
    }

    pub fn configuration(&self) -> &OAuthConnection {
        self.operation.configuration()
    }

    /// Only DeleteProviderAccount intents can enter this service. Original owner,
    /// session and source authority are checked by the transaction repository.
    pub async fn begin(&self, intent: &OAuthIntent<'_>) -> Result<GoogleAuthorizationStart> {
        self.operation.begin(intent).await
    }

    /// The trusted transport retains the original state/private proof and supplies
    /// its actual callback route. Provider errors require the same binding as codes.
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

    /// Cancel this bound pending operation without revoking its initiating session.
    pub async fn cancel(
        &self,
        intent: &OAuthIntent<'_>,
        state: &Secret,
        proof: &OAuthBrowserProof,
    ) -> Result<()> {
        self.operation.cancel(intent, state, proof).await
    }
}
