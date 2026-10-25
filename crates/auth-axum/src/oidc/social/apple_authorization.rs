use auth_core::{
    AppleAuthorizationStart, AppleIdentityLinkAuthorization, OAuthBrowserProof, OAuthIntent,
    Result, Secret,
};
use std::sync::Arc;

#[derive(Clone)]
pub(super) enum AppleLink {
    Standard(Arc<AppleIdentityLinkAuthorization>),
    #[cfg(feature = "apple-grants-web")]
    Captured {
        authorization: Arc<auth_core::AppleGrantAuthorization>,
        linking: Arc<auth_core::AppleGrantLinking>,
    },
}
impl AppleLink {
    pub(super) async fn begin(&self, intent: &OAuthIntent<'_>) -> Result<AppleAuthorizationStart> {
        match self {
            Self::Standard(authorization) => authorization.begin(intent).await,
            #[cfg(feature = "apple-grants-web")]
            Self::Captured { authorization, .. } => authorization.begin(intent).await,
        }
    }
    pub(super) async fn cancel(
        &self,
        intent: &OAuthIntent<'_>,
        state: &Secret,
        proof: &OAuthBrowserProof,
    ) -> Result<()> {
        match self {
            Self::Standard(authorization) => authorization.cancel(intent, state, proof).await,
            #[cfg(feature = "apple-grants-web")]
            Self::Captured { authorization, .. } => {
                authorization.cancel(intent, state, proof).await
            }
        }
    }
}
