use super::{apple, google, pages, types::*, unlink};
use utoipa::OpenApi;
#[derive(OpenApi)]
#[openapi(
    paths(
        google::start,
        google::finish,
        google::cancel,
        apple::start,
        apple::finish,
        apple::cancel,
        unlink::unlink,
        pages::accounts
    ),
    components(schemas(
        SocialLinkStartInput,
        GoogleLinkFinishInput,
        AppleLinkFinishInput,
        SocialLinkCancelInput,
        SocialUnlinkInput,
        SocialLinkStartResponse
    ))
)]
struct SocialApi;
pub fn social_web_openapi() -> utoipa::openapi::OpenApi {
    let mut api = crate::oidc::google_web_openapi();
    api.merge(crate::oidc::apple_web_openapi());
    api.merge(SocialApi::openapi());
    api
}
