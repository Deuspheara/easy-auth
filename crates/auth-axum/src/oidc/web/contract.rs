use super::{
    callback::__path_bridge,
    handlers::{__path_cancel, __path_finish, __path_start},
    pages::__path_sign_in_page,
    types::*,
};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(start, finish, cancel, bridge, sign_in_page),
    components(schemas(
        OidcSignInStartInput,
        OidcSignInFinishInput,
        OidcSignInCancelInput,
        OidcSignInStartResponse
    ))
)]
struct WebApi;

/// Base authentication, shared provider sign-in and purpose-bound deletion APIs.
pub fn oidc_web_openapi() -> utoipa::openapi::OpenApi {
    let mut api = super::super::oidc_account_deletion_openapi();
    api.merge(WebApi::openapi());
    api
}
