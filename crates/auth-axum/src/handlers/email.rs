use super::{Accepted, EmailInput, FinishInput};
use crate::browser::read_cookie;
use crate::error::{ApiError, ErrorResponse};
use crate::router::AppState;
use auth_core::Secret;
use axum::{
    Extension, Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::net::SocketAddr;

#[utoipa::path(post, path = "/v1/email/start", request_body = EmailInput,
    params(("Origin" = String, Header, description = "Exact configured browser origin")),
    responses((status = 202, body = Accepted, description = "Generic response; sets HttpOnly browser binding"),
    (status = 400, body = ErrorResponse), (status = 403, body = ErrorResponse),
    (status = 413, body = ErrorResponse), (status = 415, body = ErrorResponse), (status = 429, body = ErrorResponse), (status = 503, body = ErrorResponse), (status = 504, body = ErrorResponse)))]
pub(crate) async fn start(
    State(state): State<AppState>,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<EmailInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    // Missing ConnectInfo uses a shared embedded bucket; never trust Forwarded/X-Forwarded-For.
    let source = source
        .map(|Extension(ConnectInfo(addr))| addr.ip().to_string())
        .unwrap_or_else(|| "embedded".to_owned());
    let browser = state.auth.start_email(&input.email, &source).await?;
    let mut response = (StatusCode::ACCEPTED, Json(json!({"status":"accepted"}))).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        state
            .browser
            .cookie(state.browser.browser_name(), Some(&browser), 600),
    );
    Ok(response)
}
#[utoipa::path(post, path = "/v1/email/finish", request_body = FinishInput,
    params(("Origin" = String, Header), ("Cookie" = String, Header, description = "Browser binding cookie from start")),
    responses((status = 204, description = "Sets fresh HttpOnly session; clears binding cookie"), (status = 400, body = ErrorResponse),
    (status = 401, body = ErrorResponse), (status = 403, body = ErrorResponse), (status = 413, body = ErrorResponse),
    (status = 415, body = ErrorResponse), (status = 503, body = ErrorResponse), (status = 504, body = ErrorResponse)))]
pub(crate) async fn finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    input: Result<Json<FinishInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    let browser = read_cookie(&headers, state.browser.browser_name())?;
    let session = state
        .auth
        .finish_email(Secret::parse(input.token)?, browser)
        .await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        state
            .browser
            .cookie(state.browser.session_name(), Some(&session), 604800),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        state.browser.cookie(state.browser.browser_name(), None, 0),
    );
    Ok(response)
}
