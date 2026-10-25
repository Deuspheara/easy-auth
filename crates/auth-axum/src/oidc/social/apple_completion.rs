use super::SocialWebServices;
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
        let completion = self
            .apple_link
            .finish(
                &OAuthIntent {
                    browser: &transaction.browser,
                    source,
                    purpose,
                },
                &transaction.state,
                transaction.proof,
                self.apple.policy().configuration().redirect(),
                returned,
            )
            .await?;
        let identity = match completion {
            AppleAuthorizationCompletion::Verified { identity, .. } => *identity,
            AppleAuthorizationCompletion::Denied => return Err(Error::Unauthorized),
            AppleAuthorizationCompletion::ProviderFailure => return Err(Error::Unavailable),
        };
        self.linking
            .finish(self.apple.policy().map(identity)?, current)
            .await?;
        Ok(())
    }
}
