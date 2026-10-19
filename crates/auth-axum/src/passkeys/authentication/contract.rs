use super::handlers::{__path_finish, __path_start};
use super::schema::{WebAuthnAssertionResponse, WebAuthnRequestOptions};
use super::types::{
    PasskeyAuthenticationFinishInput, PasskeyAuthenticationStartInput,
    PasskeyAuthenticationStartResponse,
};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(start, finish),
    components(schemas(
        PasskeyAuthenticationStartInput,
        PasskeyAuthenticationStartResponse,
        PasskeyAuthenticationFinishInput,
        WebAuthnRequestOptions,
        WebAuthnAssertionResponse
    ))
)]
struct AuthenticationApi;

pub fn passkey_authentication_openapi() -> utoipa::openapi::OpenApi {
    let mut api = super::super::passkey_enrollment_openapi();
    api.merge(AuthenticationApi::openapi());
    api
}
