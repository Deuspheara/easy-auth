use super::schema::{WebAuthnCreationOptions, WebAuthnRegistrationResponse};
use auth_core::{PasskeyCreationOptions, PasskeyRegistrationResponse};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct PasskeyEnrollmentStartInput {
    /// Human-readable label; 1–256 UTF-8 bytes, nonblank, no control characters.
    pub(super) label: String,
    /// Explicitly request browser residence. Success is not independently verified residence metadata.
    #[serde(default)]
    #[schema(default = false)]
    pub(super) discoverable: bool,
}

#[derive(Serialize, ToSchema)]
pub(super) struct PasskeyEnrollmentStartResponse {
    pub(super) transaction_id: Uuid,
    #[schema(value_type = WebAuthnCreationOptions)]
    pub(super) options: PasskeyCreationOptions,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct PasskeyEnrollmentFinishInput {
    pub(super) transaction_id: Uuid,
    #[schema(value_type = WebAuthnRegistrationResponse)]
    pub(super) credential: PasskeyRegistrationResponse,
}

#[derive(Serialize, ToSchema)]
pub(super) struct PasskeyEnrollmentFinishResponse {
    pub(super) id: Uuid,
}
