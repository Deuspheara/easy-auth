use super::super::authentication::{WebAuthnAssertionResponse, WebAuthnRequestOptions};
use super::super::schema::{WebAuthnCreationOptions, WebAuthnRegistrationResponse};
use auth_core::{
    PasskeyAuthenticationOptions, PasskeyAuthenticationResponse, PasskeyCreationOptions,
    PasskeyRegistrationResponse,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct PasskeySignupStartInput {
    /// Presentation only: 1–256 UTF-8 bytes, nonblank, no control characters.
    pub display_name: String,
}

#[derive(Serialize, ToSchema)]
pub(super) struct PasskeySignupStartResponse {
    pub transaction_id: Uuid,
    #[schema(value_type=WebAuthnCreationOptions)]
    pub options: PasskeyCreationOptions,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct PasskeySignupRegistrationInput {
    pub transaction_id: Uuid,
    #[schema(value_type=WebAuthnRegistrationResponse)]
    pub credential: PasskeyRegistrationResponse,
}

#[derive(Serialize, ToSchema)]
pub(super) struct PasskeySignupAssertionResponse {
    pub transaction_id: Uuid,
    #[schema(value_type=WebAuthnRequestOptions)]
    pub options: PasskeyAuthenticationOptions,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct PasskeySignupFinishInput {
    pub transaction_id: Uuid,
    #[schema(value_type=WebAuthnAssertionResponse)]
    pub credential: PasskeyAuthenticationResponse,
}
