use super::super::error::TokenHttpError;
use super::{
    input,
    routing::ManagementState,
    types::{ActiveToken, InactiveToken, TokenIntrospectionResponse},
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

#[utoipa::path(post,path="/oidc/introspect",request_body(content=super::input::TokenStatusInput,content_type="application/x-www-form-urlencoded"),params(("Authorization"=Option<String>,Header)),responses((status=200,body=TokenIntrospectionResponse),(status=400),(status=401),(status=413),(status=415),(status=429),(status=503),(status=504)))]
pub(in crate::issuer_web) async fn introspect(
    State(state): State<ManagementState>,
    query: RawQuery,
    headers: HeaderMap,
    peer: Result<ConnectInfo<SocketAddr>, ExtensionRejection>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, TokenHttpError> {
    let request = input::request(query, headers, peer, body)?;
    let active = state
        .management
        .introspect_access(&request.authentication, &request.token, &request.source)
        .await?;
    Ok(Json(match active {
        Some(active) => TokenIntrospectionResponse::Active(ActiveToken::from(active)),
        None => TokenIntrospectionResponse::Inactive(InactiveToken { active: false }),
    })
    .into_response())
}
#[utoipa::path(post,path="/oidc/revoke",request_body(content=super::input::TokenStatusInput,content_type="application/x-www-form-urlencoded"),params(("Authorization"=Option<String>,Header)),responses((status=200),(status=400),(status=401),(status=413),(status=415),(status=429),(status=503),(status=504)))]
pub(in crate::issuer_web) async fn revoke(
    State(state): State<ManagementState>,
    query: RawQuery,
    headers: HeaderMap,
    peer: Result<ConnectInfo<SocketAddr>, ExtensionRejection>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, TokenHttpError> {
    let request = input::request(query, headers, peer, body)?;
    state
        .management
        .revoke_access(&request.authentication, &request.token, &request.source)
        .await?;
    Ok(StatusCode::OK.into_response())
}
