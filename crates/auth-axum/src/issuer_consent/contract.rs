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
        IssuerConsentInput,
        IssuerConsentResume,
        IssuerConsentDecision,
        IssuerConsentPreview,
        IssuerConsentReturn
    ))
)]
struct ConsentApi;
/// Optional consent/code transport; deliberately advertises no token endpoint.
pub fn issuer_consent_openapi() -> utoipa::openapi::OpenApi {
    let mut api = crate::openapi();
    api.merge(ConsentApi::openapi());
    api
}
