use super::{
    delivery::__path_bridge,
    handlers::{__path_cancel, __path_finish, __path_metadata, __path_start},
    pages::__path_sign_in,
    types::*,
};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(start, finish, cancel, metadata, bridge, sign_in),
    components(schemas(SamlEmptyInput, SamlStartResponse, SamlPostDelivery))
)]
struct SamlApi;
/// Explicit engineering-only SAML composition; normal API remains unchanged.
pub fn saml_web_openapi() -> utoipa::openapi::OpenApi {
    let mut api = crate::openapi();
    api.merge(SamlApi::openapi());
    api
}
