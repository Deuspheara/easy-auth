use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NoQuery {}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct OidcSignInStartInput {}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct OidcSignInCancelInput {}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct OidcSignInFinishInput {
    #[schema(min_length = 43, max_length = 43)]
    pub state: String,
    #[schema(min_length = 1, max_length = 2048)]
    pub code: String,
    /// Actual returned iss, never inferred from trusted configuration.
    pub issuer: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(super) struct OidcSignInStartResponse {
    /// Protocol URL contains state/nonce/S256 challenge, never a session or raw PKCE.
    pub authorization_url: String,
}
