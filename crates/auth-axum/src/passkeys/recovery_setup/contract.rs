use super::{
    handlers::{__path_confirm, __path_prepare},
    types::*,
};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(prepare, confirm),
    components(schemas(
        PrepareRecoveryCodeInput,
        ConfirmRecoveryCodeInput,
        PreparedRecoveryCodeResponse
    ))
)]
struct RecoverySetupApi;

pub fn passkey_recovery_setup_openapi() -> utoipa::openapi::OpenApi {
    let mut api = super::super::passkey_management_openapi();
    api.merge(RecoverySetupApi::openapi());
    api
}
