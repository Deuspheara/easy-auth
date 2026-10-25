use crate::{
    BrowserConfig,
    browser::{read_cookie, read_optional_cookie, read_optional_cookie_value},
};
use auth_core::{Error, Result, Secret};
use axum::{
    http::{HeaderMap, header},
    response::Response,
};

const BROWSER: &str = "__Host-auth-issuer-browser";
const OPERATION: &str = "__Host-auth-issuer-operation";
const HANDLE: &str = "__Host-auth-issuer-handle";
const LIFETIME_SECONDS: u32 = 300;

pub(crate) fn require_absent(headers: &HeaderMap) -> Result<()> {
    for name in [BROWSER, HANDLE] {
        if read_optional_cookie(headers, name)?.is_some() {
            return Err(Error::Unauthorized);
        }
    }
    if read_optional_cookie_value(headers, OPERATION)?.is_some() {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
pub(crate) fn operation(headers: &HeaderMap) -> Result<uuid::Uuid> {
    let value = read_optional_cookie_value(headers, OPERATION)?.ok_or(Error::Unauthorized)?;
    let id = uuid::Uuid::parse_str(&value).map_err(|_| Error::Unauthorized)?;
    if id.is_nil() || id.to_string() != value {
        return Err(Error::Unauthorized);
    }
    Ok(id)
}
pub(crate) fn read(headers: &HeaderMap) -> Result<(Secret, Secret)> {
    Ok((
        read_cookie(headers, BROWSER)?,
        read_cookie(headers, HANDLE)?,
    ))
}
pub(crate) fn set(
    response: &mut Response,
    config: &BrowserConfig,
    browser: &Secret,
    authorization: uuid::Uuid,
    handle: &Secret,
) {
    response.headers_mut().append(
        header::SET_COOKIE,
        config.cookie_value(
            OPERATION,
            Some(&authorization.to_string()),
            LIFETIME_SECONDS,
        ),
    );
    for (name, value) in [(BROWSER, browser), (HANDLE, handle)] {
        response.headers_mut().append(
            header::SET_COOKIE,
            config.cookie(name, Some(value), LIFETIME_SECONDS),
        );
    }
}
pub(crate) fn clear(response: &mut Response, config: &BrowserConfig) {
    for name in [BROWSER, HANDLE, OPERATION] {
        response
            .headers_mut()
            .append(header::SET_COOKIE, config.cookie(name, None, 0));
    }
}
pub(crate) fn clear_on_session_change(response: &mut Response, config: &BrowserConfig) {
    let prefix = format!("{}=", config.session_name());
    if response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|v| v.to_str().is_ok_and(|v| v.starts_with(&prefix)))
    {
        clear(response, config);
    }
}
