use crate::{Error, Result};
use url::Url;

pub(super) fn origin(input: &str, local_development: bool) -> Result<Url> {
    if input.trim() != input || input.chars().any(char::is_control) || input.contains('@') {
        return Err(Error::InvalidInput);
    }
    let origin = Url::parse(input).map_err(|_| Error::InvalidInput)?;
    let host = origin.domain().ok_or(Error::InvalidInput)?;
    if host.ends_with('.') || (host != "localhost" && !host.contains('.')) {
        return Err(Error::InvalidInput);
    }
    let secure_transport = origin.scheme() == "https";
    let explicit_local_http = local_development && host == "localhost" && origin.scheme() == "http";
    if (!secure_transport && !explicit_local_http)
        || (local_development && host != "localhost")
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
        || !origin.username().is_empty()
        || origin.password().is_some()
    {
        return Err(Error::InvalidInput);
    }
    Ok(origin)
}

pub(super) fn display_name(input: &str) -> Result<()> {
    if input.trim().is_empty() || input.len() > 256 || input.chars().any(char::is_control) {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
