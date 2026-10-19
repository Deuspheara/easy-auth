use super::handlers::{__path_finish, __path_registration, __path_start};
use super::types::{
    PasskeySignupAssertionResponse, PasskeySignupFinishInput, PasskeySignupRegistrationInput,
    PasskeySignupStartInput, PasskeySignupStartResponse,
};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(start, registration, finish),
    components(schemas(
        PasskeySignupStartInput,
        PasskeySignupStartResponse,
        PasskeySignupRegistrationInput,
        PasskeySignupAssertionResponse,
        PasskeySignupFinishInput
    ))
)]
struct SignupApi;

pub fn passkey_signup_openapi() -> utoipa::openapi::OpenApi {
    let mut api = super::super::passkey_authentication_openapi();
    api.merge(SignupApi::openapi());
    api
}
