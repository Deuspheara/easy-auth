use super::{Accepted, EmailInput, FinishInput, source_key};
use crate::browser::read_cookie;
use crate::error::{ApiError, ErrorResponse};
use crate::router::AppState;
use auth_core::{Error, Secret};
use axum::{
    Extension, Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::net::SocketAddr;
use utoipa::ToSchema;

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeleteInput {
    confirmation: String,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeleteFinishInput {
    token: String,
    confirmation: String,
}
fn clear_account_cookies(state: &AppState) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    for name in [
        state.browser.session_name(),
        state.browser.browser_name(),
        state.browser.reset_name(),
        state.browser.change_name(),
        state.browser.deletion_name(),
    ] {
        response
            .headers_mut()
            .append(header::SET_COOKIE, state.browser.cookie(name, None, 0));
    }
    response
}
#[utoipa::path(post, path="/v1/account/email/start",request_body=EmailInput,params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=202,body=Accepted,description="Proofs sent to both addresses; sets change binding cookie"),(status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),(status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),(status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(crate) async fn start_email_change(
    State(state): State<AppState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<EmailInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    let current = read_cookie(&headers, state.browser.session_name())?;
    let browser = state
        .auth
        .start_email_change(&current, &input.email, &source_key(source))
        .await?;
    let mut response =
        (StatusCode::ACCEPTED, Json(Accepted { status: "accepted" })).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        state
            .browser
            .cookie(state.browser.change_name(), Some(&browser), 300),
    );
    Ok(response)
}
#[utoipa::path(post, path="/v1/account/email/confirm",request_body=FinishInput,params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=202,body=Accepted,description="One address confirmed; confirm the other proof"),(status=204,description="Both addresses confirmed; email changed; sessions/proofs revoked; login required"),(status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),(status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),(status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(crate) async fn confirm_email_change(
    State(state): State<AppState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<FinishInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    let current = read_cookie(&headers, state.browser.session_name())?;
    let browser = read_cookie(&headers, state.browser.change_name())?;
    let complete = state
        .auth
        .confirm_email_change(
            &current,
            Secret::parse(input.token)?,
            browser,
            &source_key(source),
        )
        .await?;
    Ok(if complete {
        clear_account_cookies(&state)
    } else {
        (StatusCode::ACCEPTED, Json(Accepted { status: "accepted" })).into_response()
    })
}
#[utoipa::path(post, path="/v1/account/delete/start",request_body=DeleteInput,params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=202,body=Accepted,description="Deletion proof sent to current address; no account deleted yet"),(status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),(status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),(status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(crate) async fn start_account_deletion(
    State(state): State<AppState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<DeleteInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    if input.confirmation != "delete my account" {
        return Err(Error::InvalidInput.into());
    }
    let current = read_cookie(&headers, state.browser.session_name())?;
    let browser = state
        .auth
        .start_account_deletion(&current, &source_key(source))
        .await?;
    let mut response =
        (StatusCode::ACCEPTED, Json(Accepted { status: "accepted" })).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        state
            .browser
            .cookie(state.browser.deletion_name(), Some(&browser), 300),
    );
    Ok(response)
}
#[utoipa::path(post, path="/v1/account/delete/finish",request_body=DeleteFinishInput,params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=204,description="Authentication account deleted; cookies cleared; audit subject removed"),(status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),(status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),(status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(crate) async fn finish_account_deletion(
    State(state): State<AppState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<DeleteFinishInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    if input.confirmation != "delete my account" {
        return Err(Error::InvalidInput.into());
    }
    let current = read_cookie(&headers, state.browser.session_name())?;
    let browser = read_cookie(&headers, state.browser.deletion_name())?;
    state
        .auth
        .finish_account_deletion(
            &current,
            Secret::parse(input.token)?,
            browser,
            &source_key(source),
        )
        .await?;
    Ok(clear_account_cookies(&state))
}
