use super::handlers::{__path_finish, __path_start};
use super::schema::{WebAuthnCreationOptions, WebAuthnRegistrationResponse};
use super::types::{
    PasskeyEnrollmentFinishInput, PasskeyEnrollmentFinishResponse, PasskeyEnrollmentStartInput,
    PasskeyEnrollmentStartResponse,
};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(start, finish),
    components(schemas(
        PasskeyEnrollmentStartInput,
        PasskeyEnrollmentStartResponse,
        PasskeyEnrollmentFinishInput,
        PasskeyEnrollmentFinishResponse,
        WebAuthnCreationOptions,
        WebAuthnRegistrationResponse
    ))
)]
struct EnrollmentApi;

/// Full API for the explicit experimental enrollment composition, including base routes.
pub fn passkey_enrollment_openapi() -> utoipa::openapi::OpenApi {
    let mut api = crate::openapi();
    api.merge(EnrollmentApi::openapi());
    api
}
