use super::routing::PasskeyState;
use super::types::{
    PasskeyEnrollmentFinishInput, PasskeyEnrollmentFinishResponse, PasskeyEnrollmentStartInput,
    PasskeyEnrollmentStartResponse,
};
use crate::browser::{read_cookie, read_optional_cookie};
use crate::error::{ApiError, ErrorResponse};
use crate::handlers::source_key;
use auth_core::Secret;
use axum::{
    Extension, Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;

#[utoipa::path(post, path="/v1/passkeys/enrollment/start", request_body=PasskeyEnrollmentStartInput,
    params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=200,body=PasskeyEnrollmentStartResponse,description="Fresh authenticated enrollment options; sets/reuses HttpOnly browser binding"),
    (status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),
    (status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),
    (status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(super) async fn start(
    State(state): State<PasskeyState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<PasskeyEnrollmentStartInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    let session = read_cookie(&headers, state.browser.session_name())?;
    let browser = match read_optional_cookie(&headers, state.browser.passkey_name())? {
        Some(browser) => browser,
        None => Secret::generate()?,
    };
    let source = source_key(source);
    let started = if input.discoverable {
        state
            .enrollment
            .begin_discoverable(&session, &browser, &source, &input.label)
            .await?
    } else {
        state
            .enrollment
            .begin(&session, &browser, &source, &input.label)
            .await?
    };
    let mut response = Json(PasskeyEnrollmentStartResponse {
        transaction_id: started.transaction,
        options: started.options,
    })
    .into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        state
            .browser
            .cookie(state.browser.passkey_name(), Some(&browser), 120),
    );
    Ok(response)
}

#[utoipa::path(post, path="/v1/passkeys/enrollment/finish", request_body=PasskeyEnrollmentFinishInput,
    params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=201,body=PasskeyEnrollmentFinishResponse,description="Verified credential inserted once; no authenticated session issued"),
    (status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),
    (status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),
    (status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(super) async fn finish(
    State(state): State<PasskeyState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<PasskeyEnrollmentFinishInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    let session = read_cookie(&headers, state.browser.session_name())?;
    let browser = read_cookie(&headers, state.browser.passkey_name())?;
    let id = state
        .enrollment
        .finish(
            &session,
            &browser,
            &source_key(source),
            input.transaction_id,
            &input.credential,
        )
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(PasskeyEnrollmentFinishResponse { id }),
    )
        .into_response())
}
