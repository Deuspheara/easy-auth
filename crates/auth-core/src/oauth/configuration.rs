use crate::{Error, Result};
use url::Url;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthMixupDefense {
    RequireIssuer,
    DedicatedRedirect,
}

/// Trusted server configuration, never reconstructed from callback parameters.
/// Persist it before use and retain the returned fresh database configuration.
#[must_use = "Use the persisted connection revision to construct OAuthTransactions"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OAuthConnection {
    realm: Uuid,
    connection: Uuid,
    client: Uuid,
    revision: Uuid,
    issuer: String,
    provider_client: String,
    redirect: String,
    defense: OAuthMixupDefense,
}

impl OAuthConnection {
    pub(crate) fn validate_issuer(issuer: &str) -> Result<()> {
        secure_url(issuer, false)
    }

    pub fn new(
        realm: Uuid,
        connection: Uuid,
        client: Uuid,
        issuer: &str,
        provider_client: &str,
        redirect: &str,
        defense: OAuthMixupDefense,
    ) -> Result<Self> {
        if realm.is_nil() || connection.is_nil() || client.is_nil() {
            return Err(Error::InvalidInput);
        }
        Self::validate_issuer(issuer)?;
        secure_url(redirect, true)?;
        if provider_client.is_empty()
            || provider_client.len() > 256
            || provider_client.trim() != provider_client
            || provider_client.chars().any(char::is_control)
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            realm,
            connection,
            client,
            revision: Uuid::new_v4(),
            issuer: issuer.to_owned(),
            provider_client: provider_client.to_owned(),
            redirect: redirect.to_owned(),
            defense,
        })
    }
    pub fn realm(&self) -> Uuid {
        self.realm
    }
    pub fn connection(&self) -> Uuid {
        self.connection
    }
    pub fn client(&self) -> Uuid {
        self.client
    }
    pub fn revision(&self) -> Uuid {
        self.revision
    }
    #[cfg(feature = "oidc-identities")]
    pub(crate) fn with_persisted_revision(mut self, revision: Uuid) -> Result<Self> {
        if revision.is_nil() {
            return Err(Error::InvalidInput);
        }
        self.revision = revision;
        Ok(self)
    }
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn provider_client(&self) -> &str {
        &self.provider_client
    }
    pub fn redirect(&self) -> &str {
        &self.redirect
    }
    pub fn defense(&self) -> OAuthMixupDefense {
        self.defense
    }

    pub(super) fn validate_callback(&self, callback: &super::OAuthCallback<'_>) -> Result<()> {
        if callback.redirect != self.redirect
            || callback.issuer.is_some_and(|issuer| issuer != self.issuer)
            || (self.defense == OAuthMixupDefense::RequireIssuer && callback.issuer.is_none())
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}

fn secure_url(value: &str, redirect: bool) -> Result<()> {
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
