pub(crate) mod listing;
pub(crate) mod revocation;
pub(crate) use listing::list_sessions;
pub(crate) use revocation::{revoke_all_sessions, revoke_session};

use crate::browser::read_cookie;
use crate::error::{ApiError, ErrorResponse};
use crate::handlers::UserResponse;
use crate::router::AppState;
use crate::{Auth, BrowserConfig};
use auth_core::Secret;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};

/// Verify an application's request cookie using the shared core and configured cookie policy.
/// The caller remains responsible for domain-specific authorization.
pub async fn authenticate(
    auth: &Auth,
    browser: &BrowserConfig,
    headers: &HeaderMap,
) -> auth_core::Result<auth_core::User> {
    let secret = read_cookie(headers, browser.session_name())?;
    auth.authenticate(&secret).await
}
pub(crate) fn session_response(state: &AppState, session: &Secret) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        state
            .browser
            .cookie(state.browser.session_name(), Some(session), 604800),
    );
    response
}
#[utoipa::path(get, path = "/v1/session", params(("Cookie" = String, Header, description = "Session cookie")),
    responses((status = 200, body = UserResponse), (status = 401, body = ErrorResponse), (status = 503, body = ErrorResponse), (status = 504, body = ErrorResponse)))]
pub(crate) async fn session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let token = read_cookie(&headers, state.browser.session_name())?;
    let user = state.auth.authenticate(&token).await?;
    Ok(Json(UserResponse {
        id: user.id,
        realm_id: user.realm_id,
        email: user.email,
        display_name: user.display_name,
    })
    .into_response())
}
#[utoipa::path(post, path = "/v1/logout", params(("Origin" = String, Header), ("Cookie" = String, Header)),
    responses((status = 204, description = "Revoked and cleared session"), (status = 403, body = ErrorResponse), (status = 503, body = ErrorResponse), (status = 504, body = ErrorResponse)))]
pub(crate) async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    // Missing/invalid credentials are already logged out; duplicate cookies cannot select an identity.
    if let Ok(token) = read_cookie(&headers, state.browser.session_name()) {
        state.auth.logout(&token).await?;
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        state.browser.cookie(state.browser.session_name(), None, 0),
    );
    Ok(response)
}
