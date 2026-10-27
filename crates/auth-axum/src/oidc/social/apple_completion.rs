use super::{SocialWebServices, apple_authorization::AppleLink};
use crate::oidc::cookies::Transaction;
use auth_core::{
    AppleAuthorizationCompletion, AppleAuthorizationResponse, Error, OAuthIntent, OAuthPurpose,
    Result, Secret,
};

impl SocialWebServices {
    pub(super) async fn complete_apple_link(
        &self,
        source: &str,
        transaction: Transaction,
        purpose: OAuthPurpose,
        current: &Secret,
        returned: AppleAuthorizationResponse,
    ) -> Result<()> {
        let intent = OAuthIntent {
            browser: &transaction.browser,
            source,
            purpose,
        };
        match &self.apple_link {
            AppleLink::Standard(authorization) => {
                let completion = authorization
                    .finish(
                        &intent,
                        &transaction.state,
                        transaction.proof,
                        self.apple.policy().configuration().redirect(),
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
                self.linking
                    .finish(self.apple.policy().map(identity)?, current)
                    .await?;
            }
            #[cfg(feature = "apple-grants-web")]
            AppleLink::Captured {
                authorization,
                linking,
            } => {
                let completion = authorization
                    .finish(
                        &intent,
                        &transaction.state,
                        transaction.proof,
                        self.apple.policy().configuration().redirect(),
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
                linking
                    .finish(grant.map(self.apple.policy())?, current)
                    .await?;
            }
        }
        Ok(())
    }
}
