use super::AppleWebServices;
use crate::oidc::cookies::Transaction;
use auth_core::{
    AppleAuthorizationCompletion, AppleAuthorizationResponse, Error, OAuthIntent, OAuthPurpose,
    Result, Secret,
};

impl AppleWebServices {
    pub(super) async fn complete_sign_in(
        &self,
        source: &str,
        transaction: Transaction,
        returned: AppleAuthorizationResponse,
    ) -> Result<Secret> {
        let completion = self
            .authorization
            .finish(
                &OAuthIntent {
                    browser: &transaction.browser,
                    source,
                    purpose: OAuthPurpose::SignIn,
                },
                &transaction.state,
                transaction.proof,
                self.policy.configuration().redirect(),
                returned,
            )
            .await?;
        let identity = match completion {
            AppleAuthorizationCompletion::Verified { identity, .. } => *identity,
            AppleAuthorizationCompletion::Denied => return Err(Error::Unauthorized),
            AppleAuthorizationCompletion::ProviderFailure => return Err(Error::Unavailable),
        };
        // Unsigned initial profile is deliberately not passed into mapping/commit.
        let (_, session) = self.sign_in.finish(self.policy.map(identity)?).await?;
        Ok(session)
    }
}
