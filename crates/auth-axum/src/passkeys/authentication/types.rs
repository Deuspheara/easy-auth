use super::schema::{WebAuthnAssertionResponse, WebAuthnRequestOptions};
use auth_core::{PasskeyAuthenticationOptions, PasskeyAuthenticationResponse};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize, ToSchema)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum PasskeyAuthenticationStartInput {
    /// Opaque account hint from a remembered profile or trusted account selection.
    /// This API does not resolve email addresses to credential lists.
    AccountBound { account_id: Uuid },
    /// Modal resident-credential selection; no account is selected before proof.
    Discoverable {},
    /// Opportunistic resident-credential autofill; frontend must support conditional UI.
    Conditional {},
}

#[derive(Serialize, ToSchema)]
pub(super) struct PasskeyAuthenticationStartResponse {
    pub transaction_id: Uuid,
    #[schema(value_type=WebAuthnRequestOptions)]
    pub options: PasskeyAuthenticationOptions,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct PasskeyAuthenticationFinishInput {
    pub transaction_id: Uuid,
    #[schema(value_type=WebAuthnAssertionResponse)]
    pub credential: PasskeyAuthenticationResponse,
}
