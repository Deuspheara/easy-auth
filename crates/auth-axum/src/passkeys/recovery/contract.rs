use super::{
    binding::__path_bind_browser,
    cancellation::{__path_cancel_browser, __path_cancel_code, __path_cancel_key},
    claims::{__path_claim_status, __path_resume_claim, __path_start_claim},
    replacement::{__path_complete_recovery, __path_start_replacement, __path_verify_registration},
    types::*,
};
use utoipa::OpenApi;
#[derive(OpenApi)]
#[openapi(
    paths(
        bind_browser,
        start_claim,
        resume_claim,
        claim_status,
        cancel_browser,
        cancel_code,
        cancel_key,
        start_replacement,
        verify_registration,
        complete_recovery
    ),
    components(schemas(
        RecoveryBrowserInput,
        RecoveryCodeInput,
        RecoveryResumeInput,
        RecoveryClaimInput,
        RecoveryKeyCancellationInput,
        RecoveryClaimResponse,
        RecoveryCreationResponse,
        RecoveryAssertionResponse,
        RecoveryRegistrationInput,
        RecoveryFinishInput
    ))
)]
struct RecoveryApi;
pub fn passkey_recovery_openapi() -> utoipa::openapi::OpenApi {
    let mut api = super::super::passkey_recovery_setup_openapi();
    api.merge(RecoveryApi::openapi());
    api
}
