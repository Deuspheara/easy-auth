//! Exact callback and issuer URL admission.
use crate::{Error, Result};
use url::Url;

pub(super) fn validate(value: &str, redirect: bool) -> Result<()> {
    if value.len() > 2048
        || value.trim() != value
        || value.chars().any(|c| c.is_control() || c.is_whitespace())
        || value.contains('\\')
    {
        return Err(Error::InvalidInput);
    }
    let url = Url::parse(value).map_err(|_| Error::InvalidInput)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
        || (redirect && (url.path() == "/" || url.path().contains('%') || url.as_str() != value))
    {
        return Err(Error::InvalidInput);
    }
    // Preserve exact configured strings: issuer comparison must not normalize URLs.
    Ok(())
}
