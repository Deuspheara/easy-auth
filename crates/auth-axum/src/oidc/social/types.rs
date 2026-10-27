use auth_core::{Error, Result};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NoQuery {}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct SocialLinkStartInput {
    /// Deny-only consistency hint from the displayed account, never an owner selector.
    pub expected_owner: Uuid,
    #[schema(example = "link this account")]
    pub confirmation: String,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct GoogleLinkFinishInput {
    #[schema(min_length = 1, max_length = 8192)]
    pub query: String,
    pub confirmation: String,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct AppleLinkFinishInput {
    #[schema(min_length = 1, max_length = 32768)]
    pub response: String,
    pub confirmation: String,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct SocialLinkCancelInput {
    /// Required by callback controllers; absent means deliberately cancel current.
    pub state: Option<String>,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct SocialUnlinkInput {
    pub expected_owner: Uuid,
    pub identity: Uuid,
    #[schema(example = "unlink this account")]
    pub confirmation: String,
}
#[derive(Serialize, ToSchema)]
pub(super) struct SocialLinkStartResponse {
    pub authorization_url: String,
}
pub(super) fn confirm(value: &str, expected: &str) -> Result<()> {
    if value != expected {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
