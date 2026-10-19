use super::{boundary::bound_browser, routing::RecoveryState, types::*};
use crate::{
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
    http::HeaderMap,
};
use std::net::SocketAddr;

#[utoipa::path(post,path="/v1/passkeys/recovery/claims/start",operation_id="recovery_start_claim",request_body=RecoveryCodeInput,params(("Origin"=String,Header),("Cookie"=String,Header)),responses((status=200,body=RecoveryClaimResponse,description="Reserve saved code for the pre-bound browser; return metadata only"),(status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),(status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),(status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(super) async fn start_claim(
    State(state): State<RecoveryState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    query: Result<Query<NoQuery>, QueryRejection>,
    input: Result<Json<RecoveryCodeInput>, JsonRejection>,
) -> Result<Json<RecoveryClaimResponse>, ApiError> {
    query.map_err(|_| Error::InvalidInput)?;
    let Json(input) = input.map_err(ApiError::from)?;
    let browser = bound_browser(&state, &headers)?;
    let code = Secret::parse(input.code)?;
    let info = state
        .claims
        .begin(input.account_id, &code, &browser, &source_key(source))
        .await?;
    Ok(Json(info.into()))
}

#[utoipa::path(post,path="/v1/passkeys/recovery/claims/resume",operation_id="recovery_resume_claim",request_body=RecoveryResumeInput,params(("Origin"=String,Header),("Cookie"=String,Header)),responses((status=200,body=RecoveryClaimResponse,description="Recover the same claim after a lost response; no deadline extension or session"),(status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),(status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),(status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(super) async fn resume_claim(
    State(state): State<RecoveryState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    query: Result<Query<NoQuery>, QueryRejection>,
    input: Result<Json<RecoveryResumeInput>, JsonRejection>,
) -> Result<Json<RecoveryClaimResponse>, ApiError> {
    query.map_err(|_| Error::InvalidInput)?;
    let Json(input) = input.map_err(ApiError::from)?;
    let browser = bound_browser(&state, &headers)?;
    let info = state
        .claims
        .resume(input.account_id, &browser, &source_key(source))
        .await?;
    Ok(Json(info.into()))
}

#[utoipa::path(post,path="/v1/passkeys/recovery/claims/status",operation_id="recovery_claim_status",request_body=RecoveryClaimInput,params(("Origin"=String,Header),("Cookie"=String,Header)),responses((status=200,body=RecoveryClaimResponse,description="Timing metadata only; readiness never grants replacement authority"),(status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),(status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),(status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(super) async fn claim_status(
    State(state): State<RecoveryState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    query: Result<Query<NoQuery>, QueryRejection>,
    input: Result<Json<RecoveryClaimInput>, JsonRejection>,
) -> Result<Json<RecoveryClaimResponse>, ApiError> {
    query.map_err(|_| Error::InvalidInput)?;
    let Json(input) = input.map_err(ApiError::from)?;
    let browser = bound_browser(&state, &headers)?;
    let info = state
        .claims
        .status(
            input.account_id,
            &browser,
            &source_key(source),
            input.claim_id,
        )
        .await?;
    Ok(Json(info.into()))
}
