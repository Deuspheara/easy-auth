use super::{
    handlers::{__path_approve, __path_cancel, __path_prepare, __path_resume},
    pages::__path_authorize,
    types::*,
};
use utoipa::OpenApi;
#[derive(OpenApi)]
#[openapi(
    paths(prepare, approve, cancel, resume, authorize),
    components(schemas(
        NativeConsentInput,
        NativeConsentResume,
        NativeConsentDecision,
        NativeConsentPreview,
        NativeConsentReturn
    ))
)]
struct NativeConsentApi;
/// Optional consent/code transport; deliberately advertises no token endpoint.
pub fn issuer_native_consent_openapi() -> utoipa::openapi::OpenApi {
    let mut api = crate::issuer_consent::issuer_consent_openapi();
    api.merge(NativeConsentApi::openapi());
    api
}
