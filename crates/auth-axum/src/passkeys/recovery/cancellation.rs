use super::{
    boundary::{bound_browser, require_anonymous},
    routing::RecoveryState,
    types::*,
};
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
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;

#[utoipa::path(post,path="/v1/passkeys/recovery/claims/cancel",operation_id="recovery_cancel_browser",request_body=RecoveryClaimInput,params(("Origin"=String,Header),("Cookie"=String,Header)),responses((status=204,description="Bound browser cancels; code stays consumed; no session"),(status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),(status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),(status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(super) async fn cancel_browser(
    State(state): State<RecoveryState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    query: Result<Query<NoQuery>, QueryRejection>,
    input: Result<Json<RecoveryClaimInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| Error::InvalidInput)?;
    let Json(input) = input.map_err(ApiError::from)?;
    let browser = bound_browser(&state, &headers)?;
    state
        .claims
        .cancel(
            input.account_id,
            &browser,
            &source_key(source),
            input.claim_id,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[utoipa::path(post,path="/v1/passkeys/recovery/claims/cancel-with-code",operation_id="recovery_cancel_code",request_body=RecoveryCodeInput,params(("Origin"=String,Header),("Cookie"=String,Header)),responses((status=204,description="Reserved saved code denies its current claim only; no browser transfer or session"),(status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),(status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),(status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(super) async fn cancel_code(
    State(state): State<RecoveryState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    query: Result<Query<NoQuery>, QueryRejection>,
    input: Result<Json<RecoveryCodeInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| Error::InvalidInput)?;
    let Json(input) = input.map_err(ApiError::from)?;
    require_anonymous(&state, &headers)?;
    let code = Secret::parse(input.code)?;
    state
        .claims
        .cancel_with_code(input.account_id, &code, &source_key(source))
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[utoipa::path(post,path="/v1/passkeys/recovery/claims/cancel-with-key",operation_id="recovery_cancel_key",request_body=RecoveryKeyCancellationInput,params(("Origin"=String,Header),("Cookie"=String,Header)),responses((status=204,description="Genuine fresh key cancels current owned RP claim; no claimant ID or owner selector required"),(status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),(status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),(status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(super) async fn cancel_key(
    State(state): State<RecoveryState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    query: Result<Query<NoQuery>, QueryRejection>,
    input: Result<Json<RecoveryKeyCancellationInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| Error::InvalidInput)?;
    let Json(_) = input.map_err(ApiError::from)?;
    let session = read_cookie(&headers, state.base.browser.session_name())?;
    state
        .claims
        .cancel_current_with_key(&session, &source_key(source))
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
