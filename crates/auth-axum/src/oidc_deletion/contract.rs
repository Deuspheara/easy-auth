use super::{
    handlers::{__path_cancel, __path_finish, __path_start},
    types::*,
};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(start, finish, cancel),
    components(schemas(
        DeletionStartInput,
        DeletionFinishInput,
        DeletionCancelInput,
        DeletionStartResponse
    ))
)]
struct DeletionApi;

/// Contract for explicit opt-in provider deletion; normal OpenAPI is unchanged.
pub fn oidc_account_deletion_openapi() -> utoipa::openapi::OpenApi {
    let mut api = crate::openapi();
    api.merge(DeletionApi::openapi());
    api
}
