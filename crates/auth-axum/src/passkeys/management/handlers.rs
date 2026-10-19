use super::{routing::ManagementState, types::*};
use crate::{
    browser::{clear_auth_cookies, read_cookie},
    error::{ApiError, ErrorResponse},
    handlers::source_key,
};
use auth_core::Error;
use axum::{
    Extension, Json,
    extract::{
        ConnectInfo, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::HeaderMap,
    response::Response,
};
use std::net::SocketAddr;

#[utoipa::path(get, path="/v1/passkeys", params(("Cookie"=String,Header)),
    responses((status=200,body=PasskeyInventoryResponse,description="At most ten owned credentials; genuine fresh passkey session required"),
    (status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(super) async fn list(
    State(state): State<ManagementState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    query: Result<Query<InventoryQuery>, QueryRejection>,
) -> Result<Json<PasskeyInventoryResponse>, ApiError> {
    query.map_err(|_| Error::InvalidInput)?;
    let session = read_cookie(&headers, state.browser.session_name())?;
    let passkeys = state
        .management
        .list(&session, &source_key(source))
        .await?
        .into_iter()
        .map(PasskeyMetadata::from)
        .collect();
    Ok(Json(PasskeyInventoryResponse { passkeys }))
}

#[utoipa::path(post,path="/v1/passkeys/rename",request_body=RenamePasskeyInput,
    params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=200,body=RenamePasskeyResponse,description="Owned label/version changed; fresh passkey proof and exact version required"),
    (status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),(status=413,body=ErrorResponse),
    (status=415,body=ErrorResponse),(status=429,body=ErrorResponse),(status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(super) async fn rename(
    State(state): State<ManagementState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<RenamePasskeyInput>, JsonRejection>,
) -> Result<Json<RenamePasskeyResponse>, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    let session = read_cookie(&headers, state.browser.session_name())?;
    let version = state
        .management
        .rename(
            &session,
            &source_key(source),
            input.id,
            input.version,
            &input.label,
        )
        .await?;
    Ok(Json(RenamePasskeyResponse { version }))
}

#[utoipa::path(post,path="/v1/passkeys/remove",request_body=RemovePasskeyInput,
    params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=204,description="Owned credential removed, sessions invalidated and cookies cleared; another proven key must remain"),
    (status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),(status=413,body=ErrorResponse),
    (status=415,body=ErrorResponse),(status=429,body=ErrorResponse),(status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(super) async fn remove(
    State(state): State<ManagementState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<RemovePasskeyInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    let session = read_cookie(&headers, state.browser.session_name())?;
    state
        .management
        .remove(&session, &source_key(source), input.id, input.version)
        .await?;
    Ok(clear_auth_cookies(&state.browser))
}
