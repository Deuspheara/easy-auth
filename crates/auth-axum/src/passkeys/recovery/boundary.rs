use super::routing::RecoveryState;
use crate::{
    browser::{clear_auth_cookies, read_cookie, read_optional_cookie},
    error::ApiError,
    handlers::sessions::session_response,
};
use auth_core::{Error, Secret};
use axum::{
    http::{HeaderMap, header},
    response::Response,
};

pub(super) fn require_anonymous(
    state: &RecoveryState,
    headers: &HeaderMap,
) -> Result<(), ApiError> {
    // Even expired/unknown session cookies must be explicitly logged out first.
    // Recovery cannot silently switch an existing browser account session.
    if read_optional_cookie(headers, state.base.browser.session_name())?.is_some() {
        return Err(Error::Unauthorized.into());
    }
    Ok(())
}
pub(super) fn bound_browser(
    state: &RecoveryState,
    headers: &HeaderMap,
) -> Result<Secret, ApiError> {
    require_anonymous(state, headers)?;
    Ok(read_cookie(headers, state.base.browser.recovery_name())?)
}
pub(super) fn recovered_session(state: &RecoveryState, session: &Secret) -> Response {
    let mut response = session_response(&state.base, session);
    let cleared = clear_auth_cookies(&state.base.browser);
    let session_prefix = format!("{}=", state.base.browser.session_name());
    for cookie in cleared.headers().get_all(header::SET_COOKIE) {
        if !cookie.as_bytes().starts_with(session_prefix.as_bytes()) {
            response
                .headers_mut()
                .append(header::SET_COOKIE, cookie.clone());
        }
    }
    // Retain the independent recovery binding: it may also bind another account's
    // claim. Terminal database state prevents replay; it is never a session cookie.
    response
}
