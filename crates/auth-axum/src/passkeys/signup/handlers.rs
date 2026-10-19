use super::routing::SignupState;
use super::types::{
    PasskeySignupAssertionResponse, PasskeySignupFinishInput, PasskeySignupRegistrationInput,
    PasskeySignupStartInput, PasskeySignupStartResponse,
};
use crate::browser::{read_cookie, read_optional_cookie};
use crate::error::{ApiError, ErrorResponse};
use crate::handlers::{sessions::session_response, source_key};
use auth_core::{Error, Secret};
use axum::{
    Extension, Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;

fn require_anonymous(state: &SignupState, headers: &HeaderMap) -> Result<(), ApiError> {
    // Reject even an expired/unknown session cookie; explicitly log out first.
    // An anonymous ceremony must not silently replace an existing account session.
    if read_optional_cookie(headers, state.base.browser.session_name())?.is_some() {
        return Err(Error::Unauthorized.into());
    }
    Ok(())
}

#[utoipa::path(post,path="/v1/passkeys/signup/start",request_body=PasskeySignupStartInput,
    params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=200,body=PasskeySignupStartResponse,description="Pending resident registration; no account/session yet; sets/reuses HttpOnly binding"),
    (status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),
    (status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),
    (status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(super) async fn start(
    State(state): State<SignupState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<PasskeySignupStartInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    require_anonymous(&state, &headers)?;
    let browser = read_optional_cookie(&headers, state.base.browser.passkey_name())?
        .map(Ok)
        .unwrap_or_else(Secret::generate)?;
    let pending = state
        .signup
        .begin(&input.display_name, &browser, &source_key(source))
        .await?;
    let mut response = Json(PasskeySignupStartResponse {
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

#[utoipa::path(post,path="/v1/passkeys/signup/registration",request_body=PasskeySignupRegistrationInput,
    params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=200,body=PasskeySignupAssertionResponse,description="Verified candidate is pending; assertion still required; no session issued"),
    (status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),
    (status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),
    (status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(super) async fn registration(
    State(state): State<SignupState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<PasskeySignupRegistrationInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    require_anonymous(&state, &headers)?;
    let browser = read_cookie(&headers, state.base.browser.passkey_name())?;
    let pending = state
        .signup
        .finish_registration(
            &browser,
            &source_key(source),
            input.transaction_id,
            &input.credential,
        )
        .await?;
    Ok(Json(PasskeySignupAssertionResponse {
        transaction_id: pending.transaction,
        options: pending.options,
    })
    .into_response())
}

#[utoipa::path(post,path="/v1/passkeys/signup/finish",request_body=PasskeySignupFinishInput,
    params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=204,description="Verified assertion; atomic account/key/session/audit creation; sets fresh session cookie"),
    (status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),
    (status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),
    (status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(super) async fn finish(
    State(state): State<SignupState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<PasskeySignupFinishInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    require_anonymous(&state, &headers)?;
    let browser = read_cookie(&headers, state.base.browser.passkey_name())?;
    let session = state
        .signup
        .finish(
            &browser,
            &source_key(source),
            input.transaction_id,
            &input.credential,
        )
        .await?;
    Ok(session_response(&state.base, &session))
}
