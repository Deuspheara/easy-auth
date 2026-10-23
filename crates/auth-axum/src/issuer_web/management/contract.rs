use super::{
    handlers::{__path_introspect, __path_revoke},
    input::TokenStatusInput,
    types::{ActiveToken, InactiveToken, TokenIntrospectionResponse},
};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(introspect, revoke),
    components(schemas(
        TokenStatusInput,
        ActiveToken,
        InactiveToken,
        TokenIntrospectionResponse
    ))
)]
struct ManagementApi;
pub fn issuer_token_management_openapi() -> utoipa::openapi::OpenApi {
    let mut api = super::super::issuer_web_openapi();
    api.merge(ManagementApi::openapi());
    api
}
