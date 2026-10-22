use super::{
    delivery::__path_bridge,
    handlers::{__path_cancel, __path_finish, __path_metadata, __path_start},
    operation::{__path_select, SamlOperationInput, SamlOperationKind, SamlOperationResponse},
    pages::__path_sign_in,
    types::*,
};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(start, finish, cancel, metadata, bridge, sign_in, select),
    components(schemas(
        SamlEmptyInput,
        SamlStartResponse,
        SamlPostDelivery,
        SamlOperationInput,
        SamlOperationKind,
        SamlOperationResponse
    ))
)]
struct SamlApi;
/// Explicit engineering-only SAML composition; normal API remains unchanged.
pub fn saml_web_openapi() -> utoipa::openapi::OpenApi {
    let mut api = crate::openapi();
    api.merge(SamlApi::openapi());
    api
}

#[derive(OpenApi)]
#[openapi(
    paths(
        super::deletion::handlers::start,
        super::deletion::handlers::finish,
        super::deletion::handlers::cancel,
        super::deletion::pages::page
    ),
    components(schemas(
        super::deletion::types::SamlDeletionConfirmation,
        super::deletion::types::SamlDeletionDelivery
    ))
)]
struct SamlDeletionApi;

/// Adds only the explicitly selected gated account-deletion contract.
pub fn saml_account_deletion_web_openapi() -> utoipa::openapi::OpenApi {
    let mut api = saml_web_openapi();
    api.merge(SamlDeletionApi::openapi());
    api
}
