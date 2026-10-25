//! The explicit public native profile. Port flexibility never changes the
//! literal interface, path or the concrete return URI retained by a code flow.
use super::{MAX_ISSUER_REDIRECT_BYTES, MAX_ISSUER_REDIRECTS};
use crate::{Error, Result};
use url::{Host, Url};

pub(super) fn registration(values: &[&str]) -> Result<Vec<String>> {
    if values.is_empty() || values.len() > MAX_ISSUER_REDIRECTS {
        return Err(Error::InvalidInput);
    }
    let mut redirects = Vec::with_capacity(values.len());
    for value in values {
        let normalized = without_port(value)?;
        if redirects.contains(&normalized) {
            return Err(Error::InvalidInput);
        }
        redirects.push(normalized);
    }
    redirects.sort();
    Ok(redirects)
}

pub(super) fn permits(registered: &[String], actual: &str) -> bool {
    without_port(actual).is_ok_and(|value| registered.contains(&value))
}

fn without_port(value: &str) -> Result<String> {
    if value.is_empty()
        || value.len() > MAX_ISSUER_REDIRECT_BYTES
        || !value.is_ascii()
        || value
            .bytes()
            .any(|b| b.is_ascii_control() || b == b' ' || b == b'*')
    {
        return Err(Error::InvalidInput);
    }
    let mut url = Url::parse(value).map_err(|_| Error::InvalidInput)?;
    let prefix = match url.host() {
        Some(Host::Ipv4(address)) if address.octets() == [127, 0, 0, 1] => "http://127.0.0.1",
        Some(Host::Ipv6(address)) if address == std::net::Ipv6Addr::LOCALHOST => "http://[::1]",
        _ => return Err(Error::InvalidInput),
    };
    // URL drops an explicit default port. Admit its exact :80 spelling too,
    // because native clients may obtain any nonzero interface port. The later
    // code retains the original actual URI, not this registration projection.
    let canonical = url.as_str() == value
        || value
            .strip_prefix(&format!("{prefix}:80"))
            .is_some_and(|path| format!("{prefix}{path}") == url.as_str());
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port() == Some(0)
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() == "/"
        || !canonical
    {
        return Err(Error::InvalidInput);
    }
    url.set_port(None).map_err(|_| Error::InvalidInput)?;
    Ok(url.into())
}

#[cfg(feature = "oidc-client")]
pub(crate) fn validate_native_client_return(value: &str) -> Result<()> {
    without_port(value).map(|_| ())
}
