use super::{AppleWebServices, authorization::SignIn};
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
        let intent = OAuthIntent {
            browser: &transaction.browser,
            source,
            purpose: OAuthPurpose::SignIn,
        };
        // Each branch consumes the same original private proof exactly once and
        // delegates policy/atomicity to its concrete core/repository operation.
        let (_, session) = match &self.operation {
            SignIn::Standard {
                authorization,
                sign_in,
            } => {
                let completion = authorization
                    .finish(
                        &intent,
                        &transaction.state,
                        transaction.proof,
                        self.policy.configuration().redirect(),
                        returned,
                    )
                    .await?;
                let identity = match completion {
                    AppleAuthorizationCompletion::Verified { identity, .. } => *identity,
                    AppleAuthorizationCompletion::Denied => return Err(Error::Unauthorized),
                    AppleAuthorizationCompletion::ProviderFailure => {
                        return Err(Error::Unavailable);
                    }
                };
                // Unsigned initial profile is deliberately not mapped or committed.
                sign_in.finish(self.policy.map(identity)?).await?
            }
            #[cfg(feature = "apple-grants-web")]
            SignIn::Captured {
                authorization,
                sign_in,
            } => {
                let completion = authorization
                    .finish(
                        &intent,
                        &transaction.state,
                        transaction.proof,
                        self.policy.configuration().redirect(),
                        returned,
                    )
                    .await?;
                let grant = match completion {
                    auth_core::AppleGrantAuthorizationCompletion::Verified(grant) => *grant,
                    auth_core::AppleGrantAuthorizationCompletion::Denied => {
                        return Err(Error::Unauthorized);
                    }
                    auth_core::AppleGrantAuthorizationCompletion::ProviderFailure => {
                        return Err(Error::Unavailable);
                    }
                };
                sign_in.finish(grant.map(&self.policy)?).await?
            }
        };
        Ok(session)
    }
}
