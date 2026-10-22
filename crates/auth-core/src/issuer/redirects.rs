use crate::{Error, Result};
use url::{Host, Url};

pub const MAX_ISSUER_REDIRECTS: usize = 8;
pub const MAX_ISSUER_REDIRECT_BYTES: usize = 2048;

pub(super) fn registration(values: &[&str]) -> Result<(Vec<String>, String)> {
    if values.is_empty() || values.len() > MAX_ISSUER_REDIRECTS {
        return Err(Error::InvalidInput);
    }
    let mut redirects = Vec::with_capacity(values.len());
    let mut sector = None;
    for value in values {
        let host = endpoint(value)?;
        if sector.as_ref().is_some_and(|previous| previous != &host)
            || redirects.iter().any(|previous| previous == value)
        {
            return Err(Error::InvalidInput);
        }
        sector = Some(host);
        redirects.push((*value).to_owned());
    }
    redirects.sort();
    Ok((redirects, sector.ok_or(Error::InvalidInput)?))
}

fn endpoint(value: &str) -> Result<String> {
    if value.is_empty()
        || value.len() > MAX_ISSUER_REDIRECT_BYTES
        || !value.is_ascii()
        || value
            .bytes()
            .any(|b| b.is_ascii_control() || b == b' ' || b == b'*')
    {
        return Err(Error::InvalidInput);
    }
    let url = Url::parse(value).map_err(|_| Error::InvalidInput)?;
    let Some(Host::Domain(host)) = url.host() else {
        return Err(Error::InvalidInput);
    };
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.as_str() != value
        || host.is_empty()
        || host.len() > 253
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    {
        return Err(Error::InvalidInput);
    }
    Ok(host.to_owned())
}
