use super::super::{error::TokenHttpError, management};
use super::services::IssuerNativeWebServices;
use axum::{
    body::Bytes,
    extract::{
        ConnectInfo, RawQuery, State,
        rejection::{BytesRejection, ExtensionRejection},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;
#[utoipa::path(post,path="/oidc/revoke",operation_id="nativeIssuerRevocation",request_body(content=super::super::management::TokenStatusInput,content_type="application/x-www-form-urlencoded"),responses((status=200),(status=400),(status=401),(status=413),(status=415),(status=429),(status=503),(status=504)))]
pub(super) async fn revoke(
    State(services): State<IssuerNativeWebServices>,
    query: RawQuery,
    headers: HeaderMap,
    peer: Result<ConnectInfo<SocketAddr>, ExtensionRejection>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, TokenHttpError> {
    let request = management::status_request(query, headers, peer, body)?;
    services
        .refresh
        .revoke_registered(
            &services.management,
            &request.authentication,
            &request.token,
            &request.source,
        )
        .await?;
    Ok(StatusCode::OK.into_response())
}
