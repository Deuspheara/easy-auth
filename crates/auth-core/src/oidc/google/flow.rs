use super::{GoogleAuthorizationOutcome, GoogleAuthorizationResponse, GoogleCodeExchange};
use super::{GoogleSessionAgeCodeExchange, authorization_exchange::AuthorizationExchange};
use crate::{
    Error, OAuthBrowserProof, OAuthCallback, OAuthConnection, OAuthIntent, OAuthPurpose,
    OAuthStart, OAuthTransactions, OidcAuthorizationUrl, Result, Secret, VerifiedOidcIdentity,
};
use std::sync::Arc;

/// Retain the transaction's state/private proof in protected transient transport
/// storage. Only the authorization URL goes to the external system browser.
#[derive(Debug)]
pub struct GoogleAuthorizationStart {
    pub transaction: OAuthStart,
    pub authorization_url: OidcAuthorizationUrl,
}

/// No variant is a local session. Verified proof still needs current-policy
/// mapping and atomic persistence; denied/provider-failure variants grant nothing.
#[derive(Debug)]
pub enum GoogleAuthorizationCompletion {
    Verified(Box<VerifiedOidcIdentity>),
    Denied,
    ProviderFailure,
}

/// Shared Google sign-in orchestration for reviewed browser/native transports.
/// No HTTP route, browser launch, listener ownership or ordinary activation.
pub struct GoogleAuthorization {
    transactions: Arc<OAuthTransactions>,
    exchange: AuthorizationExchange,
}

impl GoogleAuthorization {
    pub fn new(
        transactions: Arc<OAuthTransactions>,
        exchange: Arc<GoogleCodeExchange>,
    ) -> Result<Self> {
        Self::configured(transactions, AuthorizationExchange::Ordinary(exchange))
    }

    /// Explicit eligible-client session-age profile. Claim absence remains a
    /// provider-profile failure; selecting it creates no claim or fresh event.
    pub fn new_session_age(
        transactions: Arc<OAuthTransactions>,
        exchange: Arc<GoogleSessionAgeCodeExchange>,
    ) -> Result<Self> {
        Self::configured(transactions, AuthorizationExchange::SessionAge(exchange))
    }

    fn configured(
        transactions: Arc<OAuthTransactions>,
        exchange: AuthorizationExchange,
    ) -> Result<Self> {
        if transactions.configuration() != exchange.configuration() {
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

    pub async fn begin(&self, intent: &OAuthIntent<'_>) -> Result<GoogleAuthorizationStart> {
        require_sign_in(intent)?;
        let transaction = self.transactions.begin(intent).await?;
        match self.exchange.authorization_url(&transaction).await {
            Ok(authorization_url) => Ok(GoogleAuthorizationStart {
                transaction,
                authorization_url,
            }),
            Err(error) => {
                // Clean up only the newly admitted operation. Storage failure
                // remains observable rather than claiming cancellation succeeded.
                self.transactions
                    .cancel(intent, &transaction.state, &transaction.proof)
                    .await?;
                Err(error)
            }
        }
    }

    /// The transport supplies its retained original state/private proof and the
    /// actual trusted callback route or owned listener URI. A pasted URL is not
    /// evidence of delivery. Malformed input must be rejected before calling this.
    pub async fn finish(
        &self,
        intent: &OAuthIntent<'_>,
        expected_state: &Secret,
        proof: OAuthBrowserProof,
        actual_redirect: &str,
        response: GoogleAuthorizationResponse,
    ) -> Result<GoogleAuthorizationCompletion> {
        require_sign_in(intent)?;
        let (state, issuer, outcome) = response.into_parts();
        if state.verifier() != expected_state.verifier()
            || actual_redirect != self.configuration().redirect()
            || issuer != self.configuration().issuer()
        {
            return Err(Error::Unauthorized);
        }
        let completion =
            match outcome {
                GoogleAuthorizationOutcome::Code(code) => {
                    let context = self
                        .transactions
                        .consume(
                            intent,
                            &state,
                            proof,
                            OAuthCallback {
                                redirect: actual_redirect,
                                issuer: Some(&issuer),
                            },
                        )
                        .await?;
                    return self.exchange.exchange(context, code).await.map(|identity| {
                        GoogleAuthorizationCompletion::Verified(Box::new(identity))
                    });
                }
                GoogleAuthorizationOutcome::Denied => GoogleAuthorizationCompletion::Denied,
                GoogleAuthorizationOutcome::ProviderFailure => {
                    GoogleAuthorizationCompletion::ProviderFailure
                }
            };
        self.transactions.cancel(intent, &state, &proof).await?;
        Ok(completion)
    }

    /// Explicit operation cancellation; no ambient session is revoked.
    pub async fn cancel(
        &self,
        intent: &OAuthIntent<'_>,
        state: &Secret,
        proof: &OAuthBrowserProof,
    ) -> Result<()> {
        require_sign_in(intent)?;
        self.transactions.cancel(intent, state, proof).await
    }
}

fn require_sign_in(intent: &OAuthIntent<'_>) -> Result<()> {
    if !matches!(intent.purpose, OAuthPurpose::SignIn) {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
