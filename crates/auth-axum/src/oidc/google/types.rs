use auth_core::{Error, Result};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NoQuery {}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct GoogleEmptyInput {}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct GoogleCallbackInput {
    /// Actual raw query, without a URL, question mark or fragment.
    #[schema(min_length = 1, max_length = 8192)]
    pub query: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct GoogleDeletionStartInput {
    #[schema(example = "delete my account")]
    pub confirmation: String,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct GoogleDeletionFinishInput {
    #[schema(example = "delete my account")]
    pub confirmation: String,
    /// Actual raw Google callback query; all original private bindings still apply.
    #[schema(min_length = 1, max_length = 8192)]
    pub query: String,
}
#[derive(Serialize, ToSchema)]
pub(super) struct GoogleStartResponse {
    /// Protocol URL only, never a session or raw private PKCE verifier.
    pub authorization_url: String,
}
pub(super) fn confirm(value: &str) -> Result<()> {
    if value != "delete my account" {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
