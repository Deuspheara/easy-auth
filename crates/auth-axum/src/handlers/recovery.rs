use super::{Accepted, EmailInput, source_key};
use crate::browser::read_cookie;
use crate::error::{ApiError, ErrorResponse};
use crate::router::AppState;
use auth_core::Password;
use auth_core::Secret;
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
pub(crate) struct PasswordResetInput {
    token: String,
    password: String,
}
#[utoipa::path(post, path = "/v1/password/reset/start", request_body = EmailInput,
    params(("Origin" = String, Header)), responses((status = 202, body = Accepted, description = "Generic response; sets reset binding cookie; same delivery path for every email"),
    (status = 400, body = ErrorResponse), (status = 403, body = ErrorResponse), (status = 413, body = ErrorResponse),
    (status = 415, body = ErrorResponse), (status = 429, body = ErrorResponse), (status = 503, body = ErrorResponse), (status = 504, body = ErrorResponse)))]
pub(crate) async fn start_password_reset(
    State(state): State<AppState>,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<EmailInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    let browser = state
        .auth
        .start_password_reset(&input.email, &source_key(source))
        .await?;
    let mut response =
        (StatusCode::ACCEPTED, Json(Accepted { status: "accepted" })).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        state
            .browser
            .cookie(state.browser.reset_name(), Some(&browser), 600),
    );
    Ok(response)
}
#[utoipa::path(post, path = "/v1/password/reset/finish", request_body = PasswordResetInput,
    params(("Origin" = String, Header), ("Cookie" = String, Header, description = "Reset binding cookie")),
    responses((status = 204, description = "Password replaced; all sessions and outstanding proofs invalidated; clears reset/session cookies; login required"),
    (status = 400, body = ErrorResponse), (status = 401, body = ErrorResponse), (status = 403, body = ErrorResponse),
    (status = 413, body = ErrorResponse), (status = 415, body = ErrorResponse), (status = 429, body = ErrorResponse),
    (status = 503, body = ErrorResponse), (status = 504, body = ErrorResponse)))]
pub(crate) async fn finish_password_reset(
    State(state): State<AppState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<PasswordResetInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    let browser = read_cookie(&headers, state.browser.reset_name())?;
    state
        .auth
        .finish_password_reset(
            Secret::parse(input.token)?,
            browser,
            Password::parse(input.password)?,
            &source_key(source),
        )
        .await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    for name in [state.browser.reset_name(), state.browser.session_name()] {
        response
            .headers_mut()
            .append(header::SET_COOKIE, state.browser.cookie(name, None, 0));
    }
    Ok(response)
}
