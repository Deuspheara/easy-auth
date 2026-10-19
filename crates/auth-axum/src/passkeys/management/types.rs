use auth_core::PasskeyInfo;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InventoryQuery {}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct RenamePasskeyInput {
    pub id: Uuid,
    pub version: Uuid,
    /// Presentation label; core enforces 1–256 UTF-8 bytes, nonblank and no controls.
    #[schema(min_length = 1, max_length = 256)]
    pub label: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct RemovePasskeyInput {
    pub id: Uuid,
    pub version: Uuid,
}

#[derive(Serialize, ToSchema)]
pub(super) struct PasskeyMetadata {
    id: Uuid,
    version: Uuid,
    label: String,
    created_at_ms: i64,
    #[schema(required = true)]
    last_used_at_ms: Option<i64>,
}

impl From<PasskeyInfo> for PasskeyMetadata {
    fn from(key: PasskeyInfo) -> Self {
        Self {
            id: key.id,
            version: key.version,
            label: key.label,
            created_at_ms: key.created_at_ms,
            last_used_at_ms: key.last_used_at_ms,
        }
    }
}

#[derive(Serialize, ToSchema)]
pub(super) struct PasskeyInventoryResponse {
    #[schema(max_items = 10)]
    pub passkeys: Vec<PasskeyMetadata>,
}

#[derive(Serialize, ToSchema)]
pub(super) struct RenamePasskeyResponse {
    pub version: Uuid,
}
