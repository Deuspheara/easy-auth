use crate::browser::read_cookie;
use crate::error::{ApiError, ErrorResponse};
use crate::handlers::{Accepted, EmailInput, FinishInput, sessions::session_response, source_key};
use crate::router::AppState;
use auth_core::Secret;
use axum::{
    Extension, Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;

#[utoipa::path(post,path="/v1/account/email/attachment/start",request_body=EmailInput,
    params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=202,body=Accepted,description="Generic contact proof request; fresh passkey session required; sets independent binding"),
    (status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),
    (status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),
    (status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(super) async fn start(
    State(state): State<AppState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<EmailInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    let current = read_cookie(&headers, state.browser.session_name())?;
    let binding = state
        .auth
        .start_email_attachment(&current, &input.email, &source_key(source))
        .await?;
    let mut response =
        (StatusCode::ACCEPTED, Json(Accepted { status: "accepted" })).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        state
            .browser
            .cookie(state.browser.attachment_name(), Some(&binding), 300),
    );
    Ok(response)
}

#[utoipa::path(post,path="/v1/account/email/attachment/finish",request_body=FinishInput,
    params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=204,description="Verified contact attached; UUID/policy/authentication provenance preserved; rotated session"),
    (status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),
    (status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),
    (status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(super) async fn finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<FinishInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    let current = read_cookie(&headers, state.browser.session_name())?;
    let binding = read_cookie(&headers, state.browser.attachment_name())?;
    let replacement = state
        .auth
        .finish_email_attachment(
            &current,
            Secret::parse(input.token)?,
            binding,
            &source_key(source),
        )
        .await?;
    let mut response = session_response(&state, &replacement);
    response.headers_mut().append(
        header::SET_COOKIE,
        state
            .browser
            .cookie(state.browser.attachment_name(), None, 0),
    );
    Ok(response)
}
