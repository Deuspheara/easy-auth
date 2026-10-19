use super::{routing::RecoverySetupState, types::*};
use crate::{
    browser::read_cookie,
    error::{ApiError, ErrorResponse},
    handlers::source_key,
};
use auth_core::{Error, Secret};
use axum::{
    Extension, Json,
    extract::{
        ConnectInfo, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, StatusCode},
};
use std::net::SocketAddr;

#[utoipa::path(post,path="/v1/passkeys/recovery/code/prepare",request_body=PrepareRecoveryCodeInput,
    params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=200,body=PreparedRecoveryCodeResponse,description="One-time saved-code display after pending persistence; genuine fresh passkey proof required. This is configuration, not recovery login."),
    (status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),(status=413,body=ErrorResponse),
    (status=415,body=ErrorResponse),(status=429,body=ErrorResponse),(status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(super) async fn prepare(
    State(state): State<RecoverySetupState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    query: Result<Query<NoQuery>, QueryRejection>,
    input: Result<Json<PrepareRecoveryCodeInput>, JsonRejection>,
) -> Result<Json<PreparedRecoveryCodeResponse>, ApiError> {
    query.map_err(|_| Error::InvalidInput)?;
    let Json(_) = input.map_err(ApiError::from)?;
    let session = read_cookie(&headers, state.browser.session_name())?;
    let pending = state.setup.prepare(&session, &source_key(source)).await?;
    Ok(Json(PreparedRecoveryCodeResponse {
        id: pending.id,
        code: pending.code,
    }))
}

#[utoipa::path(post,path="/v1/passkeys/recovery/code/confirm",request_body=ConfirmRecoveryCodeInput,
    params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=204,description="Saved-code configuration confirmed atomically; no session issued or policy activated"),
    (status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),(status=413,body=ErrorResponse),
    (status=415,body=ErrorResponse),(status=429,body=ErrorResponse),(status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(super) async fn confirm(
    State(state): State<RecoverySetupState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    query: Result<Query<NoQuery>, QueryRejection>,
    input: Result<Json<ConfirmRecoveryCodeInput>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    query.map_err(|_| Error::InvalidInput)?;
    let Json(input) = input.map_err(ApiError::from)?;
    let code = Secret::parse(input.code)?;
    let session = read_cookie(&headers, state.browser.session_name())?;
    state
        .setup
        .confirm(&session, &source_key(source), input.id, &code)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
