use super::super::{
    error::TokenHttpError,
    management::{self, ActiveToken, InactiveToken, TokenIntrospectionResponse},
};
use auth_core::IssuerNativeIntrospection;
use axum::{
    Json,
    body::Bytes,
    extract::{
        ConnectInfo, RawQuery, State,
        rejection::{BytesRejection, ExtensionRejection},
    },
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use std::{net::SocketAddr, sync::Arc};

#[utoipa::path(post,path="/oidc/native/introspect",operation_id="nativeConsumerIntrospection",request_body(content=super::super::management::TokenStatusInput,content_type="application/x-www-form-urlencoded"),params(("Authorization"=Option<String>,Header)),responses((status=200,body=TokenIntrospectionResponse),(status=400),(status=401),(status=413),(status=415),(status=429),(status=503),(status=504)))]
pub(super) async fn inspect(
    State(service): State<Arc<IssuerNativeIntrospection>>,
    query: RawQuery,
    headers: HeaderMap,
    peer: Result<ConnectInfo<SocketAddr>, ExtensionRejection>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, TokenHttpError> {
    let request = management::status_request(query, headers, peer, body)?;
    let active = service
        .introspect_access(&request.authentication, &request.token, &request.source)
        .await?;
    Ok(Json(match active {
        Some(token) => TokenIntrospectionResponse::Active(ActiveToken::from(token)),
        None => TokenIntrospectionResponse::Inactive(InactiveToken { active: false }),
    })
    .into_response())
}
