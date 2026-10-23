use super::{
    authorize::__path_authorize, input::RefreshForm, metadata::__path_discovery,
    revocation::__path_revoke, token::__path_exchange, types::*,
};
use utoipa::OpenApi;
#[derive(OpenApi)]
#[openapi(
    paths(discovery, exchange, revoke, authorize),
    components(schemas(
        NativeTokenForm,
        RefreshForm,
        NativeCodeTokens,
        NativeRefreshTokens,
        NativeTokenResponse
    ))
)]
struct NativeApi;
pub fn issuer_native_web_openapi() -> utoipa::openapi::OpenApi {
    let mut api = super::super::issuer_token_management_openapi();
    api.merge(crate::issuer_native_consent::issuer_native_consent_openapi());
    // These paths describe the explicit mixed-profile composition only.
    // Replace their older operations, rather than leaving conflicting schemas.
    let mut native = NativeApi::openapi();
    for path in [
        "/.well-known/openid-configuration",
        "/oidc/token",
        "/oidc/revoke",
        "/oidc/authorize",
    ] {
        api.paths.paths.remove(path);
        if let Some(item) = native.paths.paths.remove(path) {
            api.paths.paths.insert(path.into(), item);
        }
    }
    api.merge(native);
    api
}
