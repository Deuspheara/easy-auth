use super::{boundary::require_anonymous, routing::RecoveryState, types::*};
use crate::{
    browser::read_optional_cookie,
    error::{ApiError, ErrorResponse},
};
use auth_core::{Error, Secret};
use axum::{
    Json,
    extract::{
        Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};

#[utoipa::path(post,path="/v1/passkeys/recovery/browser",operation_id="recovery_bind_browser",request_body=RecoveryBrowserInput,params(("Origin"=String,Header),("Cookie"=String,Header)),responses((status=204,description="Establish or retain an independent HttpOnly browser capability before code consumption; no session or database claim"),(status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=403,body=ErrorResponse),(status=413,body=ErrorResponse),(status=415,body=ErrorResponse),(status=429,body=ErrorResponse),(status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(super) async fn bind_browser(
    State(state): State<RecoveryState>,
    headers: HeaderMap,
    query: Result<Query<NoQuery>, QueryRejection>,
    input: Result<Json<RecoveryBrowserInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| Error::InvalidInput)?;
    let Json(_) = input.map_err(ApiError::from)?;
    require_anonymous(&state, &headers)?;
    let browser = read_optional_cookie(&headers, state.base.browser.recovery_name())?
        .map(Ok)
        .unwrap_or_else(Secret::generate)?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        state.base.browser.cookie(
            state.base.browser.recovery_name(),
            Some(&browser),
            auth_core::PASSKEY_RECOVERY_LIFETIME_SECONDS as u32,
        ),
    );
    Ok(response)
}
