use super::{
    authentication,
    error::{TokenHttpError, invalid},
    form::TokenForm,
    routing::WebState,
    types::TokenResponse,
};
use auth_core::{IssuerPkceVerifier, IssuerTokenError, Secret};
use axum::{
    Json,
    body::Bytes,
    extract::{
        ConnectInfo, RawQuery, State,
        rejection::{BytesRejection, ExtensionRejection},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;

#[utoipa::path(post,path="/oidc/token",request_body(content=super::types::TokenFormSchema,content_type="application/x-www-form-urlencoded"),params(("Authorization"=Option<String>,Header)),responses((status=200,body=TokenResponse),(status=400,body=super::error::TokenErrorResponse),(status=401,body=super::error::TokenErrorResponse),(status=413),(status=415),(status=429),(status=503),(status=504)))]
pub(super) async fn exchange(
    State(state): State<WebState>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    peer: Result<ConnectInfo<SocketAddr>, ExtensionRejection>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, TokenHttpError> {
    if query.is_some() {
        return Err(invalid());
    }
    let body = body.map_err(|error| {
        TokenHttpError::InvalidRequest(if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::BAD_REQUEST
        })
    })?;
    let input = TokenForm::parse(&headers, &body)?;
    if input.grant_type != "authorization_code" {
        return Err(TokenHttpError::UnsupportedGrant);
    }
    let authentication = authentication::parse(&headers, input.client_id.as_deref())?;
    let code = Secret::parse(input.code).map_err(|_| invalid())?;
    let pkce = IssuerPkceVerifier::parse(input.code_verifier).map_err(|_| invalid())?;
    let ConnectInfo(peer) =
        peer.map_err(|_| TokenHttpError::Core(IssuerTokenError::Unavailable))?;
    // Only the trusted transport peer supplies abuse admission. No ambient
    // session cookie, body source, Origin or forwarding header can grant authority.
    let tokens = state
        .services
        .tokens
        .exchange(
            &authentication,
            &code,
            &input.redirect_uri,
            &pkce,
            &peer.ip().to_string(),
        )
        .await?;
    Ok(Json(TokenResponse {
        access_token: tokens.access_token().expose().to_owned(),
        token_type: "Bearer",
        expires_in: tokens.expires_in(),
        id_token: tokens.id_token().to_owned(),
        scope: "openid",
    })
    .into_response())
}
