use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NoQuery {}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct AppleEmptyInput {}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct AppleCallbackInput {
    /// Actual raw form; not a URL or uploaded identity token.
    #[schema(min_length = 1, max_length = 32768)]
    pub response: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct AppleCancelInput {
    /// A callback page must retain its returned public state so an old page
    /// cannot clear a newer operation. Missing means deliberate current cancel.
    #[serde(default)]
    #[schema(min_length = 43, max_length = 43)]
    pub state: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(super) struct AppleStartResponse {
    pub authorization_url: String,
}
