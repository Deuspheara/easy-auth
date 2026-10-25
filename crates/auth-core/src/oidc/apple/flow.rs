use super::{
    AppleAuthorizationOutcome, AppleAuthorizationRequest, AppleAuthorizationResponse,
    AppleCodeExchange, AppleInitialProfile,
};
use crate::{
    Error, OAuthBrowserProof, OAuthCallback, OAuthConnection, OAuthIntent, OAuthPurpose,
    OAuthStart, OAuthTransactions, Result, Secret, VerifiedOidcIdentity,
};
use std::sync::Arc;

#[derive(Debug)]
pub struct AppleAuthorizationStart {
    pub transaction: OAuthStart,
    pub request: AppleAuthorizationRequest,
}
#[derive(Debug)]
pub enum AppleAuthorizationCompletion {
    Verified {
        identity: Box<VerifiedOidcIdentity>,
        initial_profile: Option<AppleInitialProfile>,
    },
    Denied,
    ProviderFailure,
}

/// Shared backend orchestration. Web delivery and native OS adapters must retain
/// private proof and independently establish actual trusted return delivery.
pub struct AppleAuthorization {
    transactions: Arc<OAuthTransactions>,
    exchange: Arc<AppleCodeExchange>,
}
impl AppleAuthorization {
    pub fn new(
        transactions: Arc<OAuthTransactions>,
        exchange: Arc<AppleCodeExchange>,
    ) -> Result<Self> {
        if transactions.configuration() != exchange.configuration()
            || transactions.redirect() != exchange.configuration().redirect()
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            transactions,
            exchange,
        })
    }
    pub fn configuration(&self) -> &OAuthConnection {
        self.transactions.configuration()
    }

    pub async fn begin(&self, intent: &OAuthIntent<'_>) -> Result<AppleAuthorizationStart> {
        require_signin(&intent.purpose)?;
        let transaction = self.transactions.begin(intent).await?;
        match self.exchange.authorization(&transaction).await {
            Ok(request) => Ok(AppleAuthorizationStart {
                transaction,
                request,
            }),
            Err(error) => {
                self.transactions
                    .cancel(intent, &transaction.state, &transaction.proof)
                    .await?;
                Err(error)
            }
        }
    }

    pub async fn finish(
        &self,
        intent: &OAuthIntent<'_>,
        expected_state: &Secret,
        proof: OAuthBrowserProof,
        actual_redirect: &str,
        response: AppleAuthorizationResponse,
    ) -> Result<AppleAuthorizationCompletion> {
        require_signin(&intent.purpose)?;
        let (state, outcome) = response.into_parts();
        if state.verifier() != expected_state.verifier()
            || actual_redirect != self.transactions.redirect()
        {
            return Err(Error::Unauthorized);
        }
        let completion = match outcome {
            AppleAuthorizationOutcome::Code {
                code,
                initial_profile,
            } => {
                let exchange = self
                    .transactions
                    .consume(
                        intent,
                        &state,
                        proof,
                        OAuthCallback {
                            redirect: actual_redirect,
                            issuer: None,
                        },
                    )
                    .await?;
                let identity = self.exchange.exchange(exchange, code).await?;
                return Ok(AppleAuthorizationCompletion::Verified {
                    identity: Box::new(identity),
                    initial_profile,
                });
            }
            AppleAuthorizationOutcome::Denied => AppleAuthorizationCompletion::Denied,
            AppleAuthorizationOutcome::ProviderFailure => {
                AppleAuthorizationCompletion::ProviderFailure
            }
        };
        self.transactions.cancel(intent, &state, &proof).await?;
        Ok(completion)
    }

    pub async fn cancel(
        &self,
        intent: &OAuthIntent<'_>,
        state: &Secret,
        proof: &OAuthBrowserProof,
    ) -> Result<()> {
        require_signin(&intent.purpose)?;
        self.transactions.cancel(intent, state, proof).await
    }
}
fn require_signin(purpose: &OAuthPurpose) -> Result<()> {
    if matches!(purpose, OAuthPurpose::SignIn) {
        Ok(())
    } else {
        Err(Error::Unauthorized)
    }
}
