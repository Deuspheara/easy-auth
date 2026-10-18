use super::sessions::session_response;
use super::source_key;
use crate::browser::read_cookie;
use crate::error::{ApiError, ErrorResponse};
use crate::router::AppState;
use auth_core::Error;
use auth_core::Password;
use axum::{
    Extension, Json,
    extract::{ConnectInfo, State},
    http::HeaderMap,
    response::Response,
};
use serde::Deserialize;
use std::net::SocketAddr;
use utoipa::ToSchema;

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct PasswordEnrollmentInput {
    /// NFC normalized; 15–256 Unicode code points, at most 1024 UTF-8 bytes.
    password: String,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct PasswordLoginInput {
    email: String,
    password: String,
}
#[utoipa::path(post, path = "/v1/password/enroll", request_body = PasswordEnrollmentInput,
    params(("Origin" = String, Header), ("Cookie" = String, Header)),
    responses((status = 204, description = "Enrolled once; previous sessions revoked; sets replacement session cookie"),
    (status = 400, body = ErrorResponse), (status = 401, body = ErrorResponse), (status = 403, body = ErrorResponse),
    (status = 413, body = ErrorResponse), (status = 415, body = ErrorResponse), (status = 429, body = ErrorResponse),
    (status = 503, body = ErrorResponse), (status = 504, body = ErrorResponse)))]
pub(crate) async fn enroll_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<PasswordEnrollmentInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    let current = read_cookie(&headers, state.browser.session_name())?;
    let password = Password::parse(input.password)?;
    let session = state
        .auth
        .enroll_password(&current, password, &source_key(source))
        .await?;
    Ok(session_response(&state, &session))
}
#[utoipa::path(post, path = "/v1/password/login", request_body = PasswordLoginInput,
    params(("Origin" = String, Header)),
    responses((status = 204, description = "Sets fresh session cookie"), (status = 400, body = ErrorResponse),
    (status = 401, body = ErrorResponse), (status = 403, body = ErrorResponse), (status = 413, body = ErrorResponse),
    (status = 415, body = ErrorResponse), (status = 429, body = ErrorResponse), (status = 503, body = ErrorResponse),
    (status = 504, body = ErrorResponse)))]
pub(crate) async fn password_login(
    State(state): State<AppState>,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<PasswordLoginInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    let password = Password::parse(input.password).map_err(|_| Error::Unauthorized)?;
    let session = state
        .auth
        .password_login(&input.email, password, &source_key(source))
        .await?;
    Ok(session_response(&state, &session))
}
