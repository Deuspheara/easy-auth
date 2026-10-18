use auth_core::{Error, Secret};
use axum::http::{HeaderMap, header};

pub(crate) fn read_cookie(headers: &HeaderMap, name: &str) -> auth_core::Result<Secret> {
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
    Secret::parse(value.ok_or(Error::Unauthorized)?)
}
