use super::AppleAuthorization;
use crate::{
    AppleAuthorizationOutcome, AppleAuthorizationResponse, AppleInitialProfile, Error,
    OAuthBrowserProof, OAuthCallback, OAuthExchange, OAuthIntent, OidcAuthorizationCode, Result,
    Secret,
};

pub(in crate::oidc::apple) enum Admission {
    Code {
        exchange: Box<OAuthExchange>,
        code: OidcAuthorizationCode,
        initial_profile: Option<AppleInitialProfile>,
    },
    Denied,
    ProviderFailure,
}
impl AppleAuthorization {
    pub(in crate::oidc::apple) async fn admit_callback(
        &self,
        intent: &OAuthIntent<'_>,
        expected_state: &Secret,
        proof: OAuthBrowserProof,
        actual_redirect: &str,
        response: AppleAuthorizationResponse,
    ) -> Result<Admission> {
        self.purpose.require(&intent.purpose)?;
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
                return Ok(Admission::Code {
                    exchange: Box::new(exchange),
                    code,
                    initial_profile,
                });
            }
            AppleAuthorizationOutcome::Denied => Admission::Denied,
            AppleAuthorizationOutcome::ProviderFailure => Admission::ProviderFailure,
        };
        self.transactions.cancel(intent, &state, &proof).await?;
        Ok(completion)
    }
}
