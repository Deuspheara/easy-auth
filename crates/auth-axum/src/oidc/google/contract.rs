use super::{
    callback::__path_bridge,
    pages::{__path_deletion_page, __path_sign_in_page},
    signin::{__path_cancel, __path_finish, __path_start},
    types::*,
};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(start, finish, cancel, bridge, sign_in_page, deletion_page),
    components(schemas(
        GoogleEmptyInput,
        GoogleCallbackInput,
        GoogleStartResponse,
        GoogleDeletionStartInput,
        GoogleDeletionFinishInput
    ))
)]
struct GoogleApi;

#[derive(OpenApi)]
#[openapi(paths(
    super::deletion::start,
    super::deletion::finish,
    super::deletion::cancel
))]
struct DeletionApi;

pub fn google_web_openapi() -> utoipa::openapi::OpenApi {
    let mut api = crate::openapi();
    api.merge(GoogleApi::openapi());
    api.merge(DeletionApi::openapi());
    api
}
