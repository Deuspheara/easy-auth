use super::{
    AppleAuthorization, AppleAuthorizationCompletion, AppleAuthorizationResponse,
    AppleAuthorizationStart, AppleClientType, AppleCodeExchange, flow::ExpectedPurpose,
};
use crate::{
    Error, OAuthBrowserProof, OAuthConnection, OAuthIntent, OAuthTransactions, Result, Secret,
};
use std::sync::Arc;

/// Explicit web identity-link operation. It never changes ownership or issues a
/// session: verified output still requires current-policy mapping and final commit.
pub struct AppleIdentityLinkAuthorization {
    operation: AppleAuthorization,
}
impl AppleIdentityLinkAuthorization {
    pub fn new(
        transactions: Arc<OAuthTransactions>,
        exchange: Arc<AppleCodeExchange>,
    ) -> Result<Self> {
        if exchange.client_type() != AppleClientType::Web {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            operation: AppleAuthorization::configured(
                transactions,
                exchange,
                ExpectedPurpose::Link,
            )?,
        })
    }
    pub fn configuration(&self) -> &OAuthConnection {
        self.operation.configuration()
    }
    pub async fn begin(&self, intent: &OAuthIntent<'_>) -> Result<AppleAuthorizationStart> {
        self.operation.begin(intent).await
    }
    pub async fn finish(
        &self,
        intent: &OAuthIntent<'_>,
        expected_state: &Secret,
        proof: OAuthBrowserProof,
        actual_redirect: &str,
        response: AppleAuthorizationResponse,
    ) -> Result<AppleAuthorizationCompletion> {
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
