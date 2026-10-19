use super::BrowserConfig;
use auth_core::{Error, Secret};
use axum::http::{HeaderMap, header};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

pub(crate) fn read_cookie(headers: &HeaderMap, name: &str) -> auth_core::Result<Secret> {
    read_optional_cookie(headers, name)?.ok_or(Error::Unauthorized)
}

pub(crate) fn read_optional_cookie(
    headers: &HeaderMap,
    name: &str,
) -> auth_core::Result<Option<Secret>> {
    let mut value = None;
    for header in headers.get_all(header::COOKIE) {
        let header = header.to_str().map_err(|_| Error::Unauthorized)?;
        for pair in header.split(';') {
            if let Some((key, val)) = pair.trim().split_once('=')
                && key == name
            {
                if value.is_some() {
                    return Err(Error::Unauthorized);
                }
                value = Some(val.to_owned());
            }
        }
    }
    value.map(Secret::parse).transpose()
}

pub(crate) fn clear_auth_cookies(browser: &BrowserConfig) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    for name in [
        browser.session_name(),
        browser.browser_name(),
        browser.reset_name(),
        browser.change_name(),
        browser.deletion_name(),
        #[cfg(feature = "passkey-enrollment")]
        browser.passkey_name(),
    ] {
        response
            .headers_mut()
            .append(header::SET_COOKIE, browser.cookie(name, None, 0));
    }
    response
}
