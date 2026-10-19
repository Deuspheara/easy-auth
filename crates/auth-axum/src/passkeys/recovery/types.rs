use super::super::{
    authentication::{WebAuthnAssertionResponse, WebAuthnRequestOptions},
    schema::{WebAuthnCreationOptions, WebAuthnRegistrationResponse},
};
use auth_core::{
    PasskeyAuthenticationOptions, PasskeyAuthenticationResponse, PasskeyCreationOptions,
    PasskeyRecoveryClaimInfo, PasskeyRecoveryTarget, PasskeyRegistrationResponse,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NoQuery {}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryBrowserInput {}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryCodeInput {
    pub account_id: Uuid,
    #[schema(min_length = 43, max_length = 43, pattern = "^[A-Za-z0-9_-]{43}$")]
    pub code: String,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryResumeInput {
    pub account_id: Uuid,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryClaimInput {
    pub account_id: Uuid,
    pub claim_id: Uuid,
}
impl RecoveryClaimInput {
    pub(super) fn target(&self) -> PasskeyRecoveryTarget {
        PasskeyRecoveryTarget {
            user_id: self.account_id,
            claim_id: self.claim_id,
        }
    }
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryKeyCancellationInput {}
#[derive(Serialize, ToSchema)]
pub(super) struct RecoveryClaimResponse {
    pub claim_id: Uuid,
    pub expires_at_ms: i64,
    #[schema(required = true)]
    pub not_before_ms: Option<i64>,
    pub notification_required: bool,
    /// Metadata only; the server independently authorizes replacement stages.
    pub ready: bool,
}
impl From<PasskeyRecoveryClaimInfo> for RecoveryClaimResponse {
    fn from(c: PasskeyRecoveryClaimInfo) -> Self {
        Self {
            claim_id: c.id,
            expires_at_ms: c.expires_at_ms,
            not_before_ms: c.not_before_ms,
            notification_required: c.notification_required,
            ready: c.ready,
        }
    }
}
#[derive(Serialize, ToSchema)]
pub(super) struct RecoveryCreationResponse {
    pub transaction_id: Uuid,
    #[schema(value_type=WebAuthnCreationOptions)]
    pub options: PasskeyCreationOptions,
}
#[derive(Serialize, ToSchema)]
pub(super) struct RecoveryAssertionResponse {
    pub transaction_id: Uuid,
    #[schema(value_type=WebAuthnRequestOptions)]
    pub options: PasskeyAuthenticationOptions,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryRegistrationInput {
    pub account_id: Uuid,
    pub claim_id: Uuid,
    pub transaction_id: Uuid,
    #[schema(value_type=WebAuthnRegistrationResponse)]
    pub credential: PasskeyRegistrationResponse,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryFinishInput {
    pub account_id: Uuid,
    pub claim_id: Uuid,
    pub transaction_id: Uuid,
    #[schema(value_type=WebAuthnAssertionResponse)]
    pub credential: PasskeyAuthenticationResponse,
}
