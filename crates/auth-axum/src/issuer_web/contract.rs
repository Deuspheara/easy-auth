use super::{
    error::TokenErrorResponse,
    metadata::{__path_discovery, __path_jwks},
    token::__path_exchange,
    types::*,
};
use utoipa::OpenApi;
#[derive(OpenApi)]
#[openapi(
    paths(discovery, jwks, exchange),
    components(schemas(
        TokenFormSchema,
        TokenResponse,
        TokenErrorResponse,
        PublicJwkSchema,
        JwksSchema,
        DiscoverySchema
    ))
)]
struct IssuerApi;
pub fn issuer_web_openapi() -> utoipa::openapi::OpenApi {
    let mut api = crate::issuer_consent::issuer_consent_openapi();
    api.merge(IssuerApi::openapi());
    api
}
