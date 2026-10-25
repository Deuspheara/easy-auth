use super::AppleVerifiedGrant;
use crate::oidc::apple::{
    AppleAuthorization,
    flow::{Admission, ExpectedPurpose},
};
use crate::{
    AppleAuthorizationResponse, AppleAuthorizationStart, AppleClientType, AppleCodeExchange, Error,
    OAuthBrowserProof, OAuthConnection, OAuthIntent, OAuthTransactions, Result, Secret,
};
use std::sync::Arc;

#[derive(Debug)]
pub enum AppleGrantAuthorizationCompletion {
    Verified(Box<AppleVerifiedGrant>),
    Denied,
    ProviderFailure,
}
/// Explicit captured-grant flow. Default Apple authorization still discards
/// credentials and cannot acquire this result by merely compiling the feature.
pub struct AppleGrantAuthorization {
    operation: AppleAuthorization,
    exchange: Arc<AppleCodeExchange>,
}
impl AppleGrantAuthorization {
    pub fn sign_in(
        transactions: Arc<OAuthTransactions>,
        exchange: Arc<AppleCodeExchange>,
    ) -> Result<Self> {
        Ok(Self {
            operation: AppleAuthorization::new(transactions, exchange.clone())?,
            exchange,
        })
    }
    pub fn linking(
        transactions: Arc<OAuthTransactions>,
        exchange: Arc<AppleCodeExchange>,
    ) -> Result<Self> {
        if exchange.client_type() != AppleClientType::Web {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            operation: AppleAuthorization::configured(
                transactions,
                exchange.clone(),
                ExpectedPurpose::Link,
            )?,
            exchange,
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
    ) -> Result<AppleGrantAuthorizationCompletion> {
        Ok(
            match self
                .operation
                .admit_callback(intent, expected_state, proof, actual_redirect, response)
                .await?
            {
                Admission::Code { exchange, code, .. } => {
                    AppleGrantAuthorizationCompletion::Verified(Box::new(
                        self.exchange.capture_grant(*exchange, code).await?,
                    ))
                }
                Admission::Denied => AppleGrantAuthorizationCompletion::Denied,
                Admission::ProviderFailure => AppleGrantAuthorizationCompletion::ProviderFailure,
            },
        )
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
