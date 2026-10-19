use auth_core::Secret;
use serde::{Deserialize, Serialize, Serializer};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NoQuery {}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct PrepareRecoveryCodeInput {}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ConfirmRecoveryCodeInput {
    pub id: Uuid,
    #[schema(min_length = 43, max_length = 43, pattern = "^[A-Za-z0-9_-]{43}$")]
    pub code: String,
}

/// Only this protected response serializes a code. Keep Secret's global
/// Serialize/Debug prohibition and zeroization; no intermediate String copy.
#[derive(Serialize, ToSchema)]
pub(super) struct PreparedRecoveryCodeResponse {
    pub id: Uuid,
    #[serde(serialize_with = "serialize_code")]
    #[schema(value_type = String, min_length = 43, max_length = 43, pattern = "^[A-Za-z0-9_-]{43}$")]
    pub code: Secret,
}

fn serialize_code<S: Serializer>(code: &Secret, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(code.expose())
}
