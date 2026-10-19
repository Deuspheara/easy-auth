use super::{
    handlers::{__path_list, __path_remove, __path_rename},
    types::*,
};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(list, rename, remove),
    components(schemas(
        RenamePasskeyInput,
        RemovePasskeyInput,
        PasskeyMetadata,
        PasskeyInventoryResponse,
        RenamePasskeyResponse
    ))
)]
struct ManagementApi;

pub fn passkey_management_openapi() -> utoipa::openapi::OpenApi {
    let mut api = super::super::passkey_signup_openapi();
    api.merge(ManagementApi::openapi());
    api
}
