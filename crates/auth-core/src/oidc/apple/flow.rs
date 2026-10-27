mod admission;
pub(super) use admission::Admission;

use super::{
    AppleAuthorizationRequest, AppleAuthorizationResponse, AppleCodeExchange, AppleInitialProfile,
};
use crate::{
    Error, OAuthBrowserProof, OAuthConnection, OAuthIntent, OAuthPurpose, OAuthStart,
    OAuthTransactions, Result, Secret, VerifiedOidcIdentity,
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
    purpose: ExpectedPurpose,
}
pub(super) enum ExpectedPurpose {
    SignIn,
    #[cfg(feature = "oidc-linking")]
    Link,
}
impl ExpectedPurpose {
    fn require(&self, purpose: &OAuthPurpose) -> Result<()> {
        match (self, purpose) {
            (Self::SignIn, OAuthPurpose::SignIn) => Ok(()),
            #[cfg(feature = "oidc-linking")]
            (Self::Link, OAuthPurpose::Link { .. }) => Ok(()),
            _ => Err(Error::Unauthorized),
        }
    }
}
impl AppleAuthorization {
    pub fn new(
        transactions: Arc<OAuthTransactions>,
        exchange: Arc<AppleCodeExchange>,
    ) -> Result<Self> {
        Self::configured(transactions, exchange, ExpectedPurpose::SignIn)
    }

    pub(super) fn configured(
        transactions: Arc<OAuthTransactions>,
        exchange: Arc<AppleCodeExchange>,
        purpose: ExpectedPurpose,
    ) -> Result<Self> {
        if transactions.configuration() != exchange.configuration()
            || transactions.redirect() != exchange.configuration().redirect()
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            transactions,
            exchange,
            purpose,
        })
    }
    pub fn configuration(&self) -> &OAuthConnection {
        self.transactions.configuration()
    }

    pub async fn begin(&self, intent: &OAuthIntent<'_>) -> Result<AppleAuthorizationStart> {
        self.purpose.require(&intent.purpose)?;
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
        match self
            .admit_callback(intent, expected_state, proof, actual_redirect, response)
            .await?
        {
            Admission::Code {
                exchange,
                code,
                initial_profile,
            } => {
                let identity = match self.purpose {
                    ExpectedPurpose::SignIn => self.exchange.exchange(*exchange, code).await?,
                    #[cfg(feature = "oidc-linking")]
                    ExpectedPurpose::Link => {
                        self.exchange.exchange_linking(*exchange, code).await?
                    }
                };
                Ok(AppleAuthorizationCompletion::Verified {
                    identity: Box::new(identity),
                    initial_profile,
                })
            }
            Admission::Denied => Ok(AppleAuthorizationCompletion::Denied),
            Admission::ProviderFailure => Ok(AppleAuthorizationCompletion::ProviderFailure),
        }
    }

    pub async fn cancel(
        &self,
        intent: &OAuthIntent<'_>,
        state: &Secret,
        proof: &OAuthBrowserProof,
    ) -> Result<()> {
        self.purpose.require(&intent.purpose)?;
        self.transactions.cancel(intent, state, proof).await
    }
}
