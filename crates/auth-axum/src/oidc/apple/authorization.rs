use auth_core::{
    AppleAuthorization, AppleAuthorizationStart, OAuthBrowserProof, OAuthIntent, OidcSignIn,
    Result, Secret,
};
use std::sync::Arc;

// Closed trusted composition keeps each authorization paired with its matching
// final repository operation. Compiling a feature does not select capture.
#[derive(Clone)]
pub(super) enum SignIn {
    Standard {
        authorization: Arc<AppleAuthorization>,
        sign_in: Arc<OidcSignIn>,
    },
    #[cfg(feature = "apple-grants-web")]
    Captured {
        authorization: Arc<auth_core::AppleGrantAuthorization>,
        sign_in: Arc<auth_core::AppleGrantSignIn>,
    },
}
impl SignIn {
    pub(super) async fn begin(&self, intent: &OAuthIntent<'_>) -> Result<AppleAuthorizationStart> {
        match self {
            Self::Standard { authorization, .. } => authorization.begin(intent).await,
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
            Self::Standard { authorization, .. } => {
                authorization.cancel(intent, state, proof).await
            }
            #[cfg(feature = "apple-grants-web")]
            Self::Captured { authorization, .. } => {
                authorization.cancel(intent, state, proof).await
            }
        }
    }
}
