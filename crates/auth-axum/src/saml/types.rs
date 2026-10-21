use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NoQuery {}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct SamlEmptyInput {}

// Deliberately no Debug: both delivery and finish carry untrusted provider data.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct SamlPostDelivery {
    #[serde(rename = "SAMLResponse")]
    #[schema(min_length = 1, max_length = 262144)]
    pub response: String,
    #[serde(rename = "RelayState")]
    #[schema(min_length = 43, max_length = 43)]
    pub relay: String,
}
#[derive(Serialize, ToSchema)]
pub(super) struct SamlStartResponse {
    pub authorization_url: String,
}
