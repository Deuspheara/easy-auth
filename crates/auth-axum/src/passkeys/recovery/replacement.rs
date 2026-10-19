use super::{
    boundary::{bound_browser, recovered_session},
    routing::RecoveryState,
    types::*,
};
use crate::{
    error::{ApiError, ErrorResponse},
    handlers::source_key,
};
use auth_core::{Error, PasskeyRecoveryTarget};
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

#[utoipa::path(post,path="/v1/passkeys/recovery/replacement/start",operation_id="recovery_start_replacement",request_body=RecoveryClaimInput,params(("Origin"=String,Header),("Cookie"=String,Header)),responses((status=200,body=RecoveryCreationResponse,description="Ready claim authorizes private candidate registration; no normal key or session"),(status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),(status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),(status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(super) async fn start_replacement(
    State(state): State<RecoveryState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    query: Result<Query<NoQuery>, QueryRejection>,
    input: Result<Json<RecoveryClaimInput>, JsonRejection>,
) -> Result<Json<RecoveryCreationResponse>, ApiError> {
    query.map_err(|_| Error::InvalidInput)?;
    let Json(input) = input.map_err(ApiError::from)?;
    let browser = bound_browser(&state, &headers)?;
    let pending = state
        .replacement
        .begin(input.target(), &browser, &source_key(source))
        .await?;
    Ok(Json(RecoveryCreationResponse {
        transaction_id: pending.transaction,
        options: pending.options,
    }))
}

#[utoipa::path(post,path="/v1/passkeys/recovery/replacement/registration",operation_id="recovery_verify_registration",request_body=RecoveryRegistrationInput,params(("Origin"=String,Header),("Cookie"=String,Header)),responses((status=200,body=RecoveryAssertionResponse,description="Exact registration advances private candidate; signed assertion still required"),(status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),(status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),(status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(super) async fn verify_registration(
    State(state): State<RecoveryState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    query: Result<Query<NoQuery>, QueryRejection>,
    input: Result<Json<RecoveryRegistrationInput>, JsonRejection>,
) -> Result<Json<RecoveryAssertionResponse>, ApiError> {
    query.map_err(|_| Error::InvalidInput)?;
    let Json(input) = input.map_err(ApiError::from)?;
    let browser = bound_browser(&state, &headers)?;
    let target = PasskeyRecoveryTarget {
        user_id: input.account_id,
        claim_id: input.claim_id,
    };
    let pending = state
        .replacement
        .finish_registration(
            target,
            input.transaction_id,
            &browser,
            &source_key(source),
            &input.credential,
        )
        .await?;
    Ok(Json(RecoveryAssertionResponse {
        transaction_id: pending.transaction,
        options: pending.options,
    }))
}

#[utoipa::path(post,path="/v1/passkeys/recovery/replacement/finish",operation_id="recovery_complete_recovery",request_body=RecoveryFinishInput,params(("Origin"=String,Header),("Cookie"=String,Header)),responses((status=204,description="Actual replacement assertion commits one-use recovery and sets fresh session; replay issues no grant"),(status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),(status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),(status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(super) async fn complete_recovery(
    State(state): State<RecoveryState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    query: Result<Query<NoQuery>, QueryRejection>,
    input: Result<Json<RecoveryFinishInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| Error::InvalidInput)?;
    let Json(input) = input.map_err(ApiError::from)?;
    let browser = bound_browser(&state, &headers)?;
    let target = PasskeyRecoveryTarget {
        user_id: input.account_id,
        claim_id: input.claim_id,
    };
    let session = state
        .replacement
        .finish(
            target,
            input.transaction_id,
            &browser,
            &source_key(source),
            &input.credential,
        )
        .await?;
    Ok(recovered_session(&state, &session))
}
