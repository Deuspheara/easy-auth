use super::{
    delivery::__path_bridge,
    operation::{__path_operation, AppleReturnOperation, AppleReturnOperationInput},
    pages::__path_sign_in,
    signin::{__path_cancel, __path_finish, __path_start},
    types::*,
};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(start, finish, cancel, bridge, sign_in, operation),
    components(schemas(
        AppleReturnOperationInput,
        AppleReturnOperation,
        AppleEmptyInput,
        AppleCallbackInput,
        AppleCancelInput,
        AppleStartResponse
    ))
)]
struct AppleApi;
pub fn apple_web_openapi() -> utoipa::openapi::OpenApi {
    let mut api = crate::openapi();
    api.merge(AppleApi::openapi());
    api
}
