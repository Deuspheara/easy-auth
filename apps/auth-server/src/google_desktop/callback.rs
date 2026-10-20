use auth_core::{
    GoogleAuthorization, GoogleAuthorizationCompletion, GoogleAuthorizationResponse,
    OAuthBrowserProof, OAuthIntent, Result, Secret,
};
use std::fmt;

/// Finite transport outcomes, separate from provider/proof/storage failures.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GoogleDesktopError {
    InvalidInput,
    Unavailable,
    Expired,
    Cancelled,
    RequestLimit,
}
impl fmt::Display for GoogleDesktopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid desktop return configuration",
            Self::Unavailable => "desktop return transport unavailable",
            Self::Expired => "desktop return expired",
            Self::Cancelled => "desktop return cancelled",
            Self::RequestLimit => "desktop return request limit reached",
        })
    }
}
impl std::error::Error for GoogleDesktopError {}

/// Actual owned-listener delivery only. No public constructor, Clone or Serialize.
/// Receiving a callback is not provider verification or a local session grant.
pub struct GoogleDesktopCallback {
    response: GoogleAuthorizationResponse,
    redirect: String,
}
impl GoogleDesktopCallback {
    pub(super) fn received(response: GoogleAuthorizationResponse, redirect: String) -> Self {
        Self { response, redirect }
    }

    /// Bind actual delivery to the original retained operation using the shared
    /// use case. Any final local commit must still retain all original authority.
    pub async fn finish(
        self,
        service: &GoogleAuthorization,
        intent: &OAuthIntent<'_>,
        state: &Secret,
        proof: OAuthBrowserProof,
    ) -> Result<GoogleAuthorizationCompletion> {
        service
            .finish(intent, state, proof, &self.redirect, self.response)
            .await
    }
}
impl fmt::Debug for GoogleDesktopCallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GoogleDesktopCallback([REDACTED])")
    }
}
