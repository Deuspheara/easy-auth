use super::routing::AuthenticationState;
use super::types::{
    PasskeyAuthenticationFinishInput, PasskeyAuthenticationStartInput,
    PasskeyAuthenticationStartResponse,
};
use crate::browser::{read_cookie, read_optional_cookie};
use crate::error::{ApiError, ErrorResponse};
use crate::handlers::{sessions::session_response, source_key};
use auth_core::Secret;
use axum::{
    Extension, Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;

#[utoipa::path(post,path="/v1/passkeys/authentication/start",request_body=PasskeyAuthenticationStartInput,
    params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=200,body=PasskeyAuthenticationStartResponse,description="Persisted browser-bound options; sets/reuses HttpOnly binding cookie"),
    (status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),
    (status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),
    (status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(super) async fn start(
    State(state): State<AuthenticationState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<PasskeyAuthenticationStartInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    let browser = read_optional_cookie(&headers, state.base.browser.passkey_name())?
        .map(Ok)
        .unwrap_or_else(Secret::generate)?;
    let source = source_key(source);
    let pending = match input {
        PasskeyAuthenticationStartInput::AccountBound { account_id } => {
            state
                .sign_in
                .begin_account(account_id, &browser, &source)
                .await?
        }
        PasskeyAuthenticationStartInput::Discoverable {} => {
            state.sign_in.begin_modal(&browser, &source).await?
        }
        PasskeyAuthenticationStartInput::Conditional {} => {
            state.sign_in.begin_discoverable(&browser, &source).await?
        }
    };
    let mut response = Json(PasskeyAuthenticationStartResponse {
        transaction_id: pending.transaction,
        options: pending.options,
    })
    .into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        state
            .base
            .browser
            .cookie(state.base.browser.passkey_name(), Some(&browser), 120),
    );
    Ok(response)
}

#[utoipa::path(post,path="/v1/passkeys/authentication/finish",request_body=PasskeyAuthenticationFinishInput,
    params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=204,description="Atomic verified credential update/session/audit; sets fresh session cookie"),
    (status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),
    (status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),
    (status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(super) async fn finish(
    State(state): State<AuthenticationState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<PasskeyAuthenticationFinishInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    let browser = read_cookie(&headers, state.base.browser.passkey_name())?;
    let session = state
        .sign_in
        .finish(
            &browser,
            &source_key(source),
            input.transaction_id,
            &input.credential,
        )
        .await?;
    Ok(session_response(&state.base, &session))
}
