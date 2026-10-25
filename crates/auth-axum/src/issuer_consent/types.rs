use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct IssuerConsentInput {
    pub client_id: Uuid,
    pub response_type: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub nonce: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct IssuerConsentDecision {
    pub authorization: Uuid,
}
#[derive(Serialize, ToSchema)]
pub(super) struct IssuerConsentPreview {
    pub authorization: Uuid,
    pub client_id: Uuid,
    pub redirect_uri: String,
    pub expires_at_us: i64,
}
#[derive(Serialize, ToSchema)]
pub(super) struct IssuerConsentReturn {
    pub redirect_uri: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NoQuery {}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct IssuerConsentResume {}
