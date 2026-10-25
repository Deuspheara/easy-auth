use super::public_address;
use crate::{Error, OAuthConnection, Result};
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};
use url::{Host, Url};

pub const MAX_OIDC_DNS_ANSWERS: usize = 16;
const MAX_ORIGINS: usize = 8;
const MAX_URL_BYTES: usize = 2048;

/// Only the core can construct a checked target. Implementations must connect to
/// these addresses without another DNS lookup, proxy or redirect; retain URL SNI.
pub struct OidcTarget {
    url: Url,
    addresses: Vec<SocketAddr>,
}
impl OidcTarget {
    pub fn url(&self) -> &Url {
        &self.url
    }
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }
}
impl fmt::Debug for OidcTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcTarget([REDACTED])")
    }
}

pub(super) struct Policy {
    origins: Vec<String>,
    issuer: String,
}
impl Policy {
    pub(super) fn new(connection: &OAuthConnection, origins: &[&str]) -> Result<Self> {
        Self::for_issuer(connection.issuer(), origins)
    }
    pub(super) fn for_issuer(issuer: &str, origins: &[&str]) -> Result<Self> {
        if origins.is_empty() || origins.len() > MAX_ORIGINS {
            return Err(Error::InvalidInput);
        }
        let mut accepted = Vec::new();
        for origin in origins {
            let url = https_url(origin)?;
            let canonical = url.origin().ascii_serialization();
            if url.path() != "/"
                || url.query().is_some()
                || canonical != *origin
                || accepted.contains(&canonical)
            {
                return Err(Error::InvalidInput);
            }
            accepted.push(canonical);
        }
        let policy = Self {
            origins: accepted,
            issuer: issuer.to_owned(),
        };
        policy.endpoint(issuer).map_err(|_| Error::InvalidInput)?;
        Ok(policy)
    }
    pub(super) fn discovery_url(&self) -> Result<Url> {
        self.endpoint(&format!(
            "{}/.well-known/openid-configuration",
            self.issuer.trim_end_matches('/')
        ))
    }
    pub(super) fn endpoint(&self, input: &str) -> Result<Url> {
        let url = https_url(input).map_err(|_| Error::Unavailable)?;
        if !self.origins.contains(&url.origin().ascii_serialization()) {
            return Err(Error::Unavailable);
        }
        let literal = match url.host() {
            Some(Host::Ipv4(address)) => Some(IpAddr::V4(address)),
            Some(Host::Ipv6(address)) => Some(IpAddr::V6(address)),
            _ => None,
        };
        if literal.is_some_and(|address| !public_address::allowed(address)) {
            return Err(Error::Unavailable);
        }
        Ok(url)
    }
    pub(super) fn target(&self, url: Url, addresses: Vec<SocketAddr>) -> Result<OidcTarget> {
        self.endpoint(url.as_str())?;
        let port = url.port_or_known_default().ok_or(Error::Unavailable)?;
        if addresses.is_empty()
            || addresses.len() > MAX_OIDC_DNS_ANSWERS
            || addresses
                .iter()
                .any(|address| address.port() != port || !public_address::allowed(address.ip()))
            || literal(&url).is_some_and(|ip| addresses.as_slice() != [SocketAddr::new(ip, port)])
        {
            return Err(Error::Unavailable);
        }
        Ok(OidcTarget { url, addresses })
    }
}

fn https_url(input: &str) -> Result<Url> {
    if input.is_empty()
        || input.len() > MAX_URL_BYTES
        || input.contains('\\')
        || input.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(Error::InvalidInput);
    }
    let url = Url::parse(input).map_err(|_| Error::InvalidInput)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.port_or_known_default() == Some(0)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.host_str().is_some_and(|host| host.contains('*'))
    {
        return Err(Error::InvalidInput);
    }
    Ok(url)
}

pub(super) fn literal(url: &Url) -> Option<IpAddr> {
    match url.host()? {
        Host::Ipv4(ip) => Some(IpAddr::V4(ip)),
        Host::Ipv6(ip) => Some(IpAddr::V6(ip)),
        Host::Domain(_) => None,
    }
}
