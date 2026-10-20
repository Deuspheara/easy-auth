//! Exact callback and issuer URL admission.
use crate::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use url::Url;

/// Trusted exact return URI. Web construction remains HTTPS-only; desktop
/// loopback is an explicit opt-in, never inferred from callback input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OAuthRedirect(String);

impl OAuthRedirect {
    pub fn https(value: &str) -> Result<Self> {
        validate(value, true)?;
        Ok(Self(value.to_owned()))
    }

    /// Call only after owning the actual desktop listener. This validates its
    /// address, not socket ownership or mobile/provider registration support.
    /// Retain this exact URI through authorization, callback and code exchange.
    pub fn desktop_loopback(listener: SocketAddr, path: &str) -> Result<Self> {
        if !matches!(listener.ip(), IpAddr::V4(ip) if ip == Ipv4Addr::LOCALHOST)
            && !matches!(listener.ip(), IpAddr::V6(ip) if ip == Ipv6Addr::LOCALHOST)
            || listener.port() == 0
            // URL serialization drops port 80; require a concrete nondefault
            // listener port rather than accepting two redirect spellings.
            || listener.port() == 80
            || path.len() > 2048
            || !path.starts_with('/')
            || path.starts_with("//")
        {
            return Err(Error::InvalidInput);
        }
        let value = format!("http://{listener}{path}");
        let url = bounded_url(&value)?;
        require_canonical_callback(&url, &value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub(super) fn into_string(self) -> String {
        self.0
    }
}

pub(super) fn validate(value: &str, redirect: bool) -> Result<()> {
    let url = bounded_url(value)?;
    if url.scheme() != "https" {
        return Err(Error::InvalidInput);
    }
    if redirect {
        require_canonical_callback(&url, value)?;
    }
    // Preserve exact configured strings: issuer comparison must not normalize URLs.
    Ok(())
}

fn bounded_url(value: &str) -> Result<Url> {
    if value.len() > 2048
        || value.trim() != value
        || value.chars().any(|c| c.is_control() || c.is_whitespace())
        || value.contains('\\')
    {
        return Err(Error::InvalidInput);
    }
    let url = Url::parse(value).map_err(|_| Error::InvalidInput)?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return Err(Error::InvalidInput);
    }
    Ok(url)
}

fn require_canonical_callback(url: &Url, value: &str) -> Result<()> {
    if url.path() == "/" || url.path().contains('%') || url.as_str() != value {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
