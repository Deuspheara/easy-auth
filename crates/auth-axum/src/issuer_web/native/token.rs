use super::super::{
    authentication,
    error::{TokenHttpError, invalid},
    types::TokenResponse,
};
use super::{
    input::{NativeTokenForm as Input, RefreshForm},
    services::IssuerNativeWebServices,
    types::*,
};
use auth_core::{
    ISSUER_NATIVE_SCOPE, IssuerClientTokens, IssuerPkceVerifier, IssuerPresentedToken,
    IssuerTokenError, Secret,
};
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

#[utoipa::path(post,path="/oidc/token",operation_id="nativeIssuerToken",request_body(content=NativeTokenForm,content_type="application/x-www-form-urlencoded"),params(("Authorization"=Option<String>,Header)),responses((status=200,body=NativeTokenResponse),(status=400,body=super::super::error::TokenErrorResponse),(status=401),(status=413),(status=415),(status=429),(status=503),(status=504)))]
pub(super) async fn exchange(
    State(services): State<IssuerNativeWebServices>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    peer: Result<ConnectInfo<SocketAddr>, ExtensionRejection>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, TokenHttpError> {
    if query.is_some() {
        return Err(invalid());
    }
    let body = body.map_err(|e| {
        TokenHttpError::InvalidRequest(if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::BAD_REQUEST
        })
    })?;
    let input = Input::parse(&headers, &body)?;
    let ConnectInfo(peer) =
        peer.map_err(|_| TokenHttpError::Core(IssuerTokenError::Unavailable))?;
    let source = peer.ip().to_string();
    let response = match input {
        Input::Code(input) => {
            let auth = authentication::parse(&headers, input.client_id.as_deref())?;
            let code = Secret::parse(input.code).map_err(|_| invalid())?;
            let pkce = IssuerPkceVerifier::parse(input.code_verifier).map_err(|_| invalid())?;
            match services
                .tokens
                .exchange_registered(
                    &services.base.tokens,
                    &auth,
                    &code,
                    &input.redirect_uri,
                    &pkce,
                    &source,
                )
                .await?
            {
                IssuerClientTokens::Online(t) => NativeTokenResponse::Online(TokenResponse {
                    access_token: t.access_token().expose().into(),
                    token_type: "Bearer",
                    expires_in: t.expires_in(),
                    id_token: t.id_token().into(),
                    scope: "openid",
                }),
                IssuerClientTokens::Native(t) => NativeTokenResponse::Native(NativeCodeTokens {
                    access_token: t.access_token().expose().into(),
                    token_type: "Bearer",
                    expires_in: t.expires_in(),
                    id_token: t.id_token().into(),
                    refresh_token: t.refresh_token().expose().into(),
                    refresh_expires_in: t.refresh_expires_in(),
                    scope: ISSUER_NATIVE_SCOPE,
                }),
            }
        }
        Input::Refresh(input) => {
            // Closed grant/scope selectors were validated during decoding; they
            // are not credentials and do not reach the authority transaction.
            let RefreshForm {
                client_id,
                refresh_token,
                grant_type: _grant_type,
                scope: _scope,
            } = input;
            let auth = authentication::parse(&headers, client_id.as_deref())?;
            let token = IssuerPresentedToken::parse(refresh_token).map_err(|_| invalid())?;
            let t = services.refresh.refresh(&auth, &token, &source).await?;
            NativeTokenResponse::Refresh(NativeRefreshTokens {
                access_token: t.access_token().expose().into(),
                token_type: "Bearer",
                expires_in: t.expires_in(),
                refresh_token: t.refresh_token().expose().into(),
                refresh_expires_in: t.refresh_expires_in(),
                scope: ISSUER_NATIVE_SCOPE,
            })
        }
    };
    Ok(Json(response).into_response())
}
