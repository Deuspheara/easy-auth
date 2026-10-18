use crate::browser::{clear_auth_cookies, read_cookie};
use crate::error::{ApiError, ErrorResponse};
use crate::handlers::source_key;
use crate::router::AppState;
use axum::{
    Extension, Json,
    extract::{ConnectInfo, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::net::SocketAddr;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevokeSessionInput {
    /// A public session ID, not a bearer secret.
    id: Uuid,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevokeAllInput {}

#[utoipa::path(post,path="/v1/sessions/revoke",request_body=RevokeSessionInput,
    params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=204,description="Owned session revoked; unknown/foreign/inactive IDs are the same no-op. Current-session revocation clears cookies"),
    (status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),(status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),(status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(crate) async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<RevokeSessionInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    let current = read_cookie(&headers, state.browser.session_name())?;
    let revoked_current = state
        .auth
        .revoke_session(&current, input.id, &source_key(source))
        .await?;
    Ok(if revoked_current {
        clear_auth_cookies(&state.browser)
    } else {
        StatusCode::NO_CONTENT.into_response()
    })
}

#[utoipa::path(post,path="/v1/sessions/revoke-all",request_body=RevokeAllInput,
    params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=204,description="All owned sessions including caller revoked, pending proofs canceled, cookies cleared; new login required"),
    (status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),(status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),(status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(crate) async fn revoke_all_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<RevokeAllInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(_) = input.map_err(ApiError::from)?;
    let current = read_cookie(&headers, state.browser.session_name())?;
    state
        .auth
        .revoke_all_sessions(&current, &source_key(source))
        .await?;
    Ok(clear_auth_cookies(&state.browser))
}
