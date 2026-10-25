use super::{OidcClientError, OidcClientResult};
use crate::{OidcClientAuthentication, oidc::policy::Policy};
use std::{fmt, net::SocketAddr};
use url::Url;
use uuid::Uuid;

/// Immutable relying-party configuration, not an issuer registration or a
/// server-side exchange proof. Provision the matching issuer client separately.
pub struct OidcClientConfiguration {
    pub(super) issuer: String,
    pub(super) client: Uuid,
    pub(super) redirect: String,
    pub(super) authentication: OidcClientAuthentication,
    pub(super) offline: bool,
}
impl OidcClientConfiguration {
    pub fn web(
        issuer: &str,
        client: Uuid,
        redirect: &str,
        authentication: OidcClientAuthentication,
    ) -> OidcClientResult<Self> {
        let uri = Url::parse(redirect).map_err(|_| OidcClientError::Configuration)?;
        if uri.scheme() != "https" || uri.as_str() != redirect {
            return Err(OidcClientError::Configuration);
        }
        Self::validated(issuer, client, redirect, authentication, false)
    }
    /// Bind the actual literal-interface listener before constructing this
    /// configuration. Address validation alone does not prove socket ownership.
    pub fn native(
        issuer: &str,
        client: Uuid,
        listener: SocketAddr,
        path: &str,
        offline: bool,
    ) -> OidcClientResult<Self> {
        if listener.port() == 0 || !path.starts_with('/') || path.starts_with("//") {
            return Err(OidcClientError::Configuration);
        }
        let redirect = format!("http://{listener}{path}");
        crate::issuer::validate_native_client_return(&redirect)
            .map_err(|_| OidcClientError::Configuration)?;
        Self::validated(
            issuer,
            client,
            &redirect,
            OidcClientAuthentication::Public,
            offline,
        )
    }
    fn validated(
        issuer: &str,
        client: Uuid,
        redirect: &str,
        authentication: OidcClientAuthentication,
        offline: bool,
    ) -> OidcClientResult<Self> {
        let parsed = Url::parse(issuer).map_err(|_| OidcClientError::Configuration)?;
        if client.is_nil()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || matches!(
                authentication,
                OidcClientAuthentication::ClientSecretPost(_)
            )
        {
            return Err(OidcClientError::Configuration);
        }
        Policy::for_issuer(issuer, &[&parsed.origin().ascii_serialization()])
            .map_err(|_| OidcClientError::Configuration)?;
        let uri = Url::parse(redirect).map_err(|_| OidcClientError::Configuration)?;
        if redirect.len() > 2048
            || redirect
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
            || redirect.contains('\\')
            || uri.host_str().is_none()
            || !uri.username().is_empty()
            || uri.password().is_some()
            || uri.fragment().is_some()
            || uri.path() == "/"
            || super::callback::fields(uri.query().unwrap_or_default())
                .map_err(|_| OidcClientError::Configuration)?
                .keys()
                .any(|name| {
                    matches!(
                        name.as_str(),
                        "code" | "state" | "iss" | "error" | "error_description" | "error_uri"
                    )
                })
        {
            return Err(OidcClientError::Configuration);
        }
        Ok(Self {
            issuer: issuer.into(),
            client,
            redirect: redirect.into(),
            authentication,
            offline,
        })
    }
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn client(&self) -> Uuid {
        self.client
    }
    pub fn redirect_uri(&self) -> &str {
        &self.redirect
    }
    pub(super) fn policy(&self) -> OidcClientResult<Policy> {
        let url = Url::parse(&self.issuer).map_err(|_| OidcClientError::Configuration)?;
        Policy::for_issuer(&self.issuer, &[&url.origin().ascii_serialization()])
            .map_err(|_| OidcClientError::Configuration)
    }
}
impl fmt::Debug for OidcClientConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcClientConfiguration([REDACTED])")
    }
}
