use auth_core::{Error, Result};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NoQuery {}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct DeletionStartInput {
    /// Exact case-sensitive phrase: delete my account.
    #[schema(example = "delete my account")]
    pub confirmation: String,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct DeletionFinishInput {
    /// Exact case-sensitive phrase: delete my account.
    #[schema(example = "delete my account")]
    pub confirmation: String,
    #[schema(min_length = 43, max_length = 43)]
    pub state: String,
    #[schema(min_length = 1, max_length = 2048)]
    pub code: String,
    /// Actual callback iss, never inferred from trusted configuration.
    pub issuer: Option<String>,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct DeletionCancelInput {}

#[derive(Serialize, ToSchema)]
pub(super) struct DeletionStartResponse {
    /// Deliberate protocol redirect. Contains state/nonce, never raw PKCE/session.
    pub authorization_url: String,
}

pub(super) fn confirm(value: &str) -> Result<()> {
    if value != "delete my account" {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
