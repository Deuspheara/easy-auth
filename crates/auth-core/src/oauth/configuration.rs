use super::OAuthRedirect;
use crate::{Error, Result};
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
        super::redirect::validate(issuer, false)
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
        Self::with_redirect(
            realm,
            connection,
            client,
            issuer,
            provider_client,
            OAuthRedirect::https(redirect)?,
            defense,
        )
    }

    /// Explicit trusted redirect profile. Desktop loopback values must come from
    /// an owned listener, never a request URL or a production web configuration.
    pub fn with_redirect(
        realm: Uuid,
        connection: Uuid,
        client: Uuid,
        issuer: &str,
        provider_client: &str,
        redirect: OAuthRedirect,
        defense: OAuthMixupDefense,
    ) -> Result<Self> {
        if realm.is_nil() || connection.is_nil() || client.is_nil() {
            return Err(Error::InvalidInput);
        }
        Self::validate_issuer(issuer)?;
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
            redirect: redirect.into_string(),
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
    /// Fresh administrative metadata only. Persistence must atomically replace
    /// the definition, retain disable and cancel prior-revision pending work.
    /// Immutable validated fields preserve their explicit redirect profile.
    pub fn reconfigured(&self) -> Self {
        let mut next = self.clone();
        next.revision = Uuid::new_v4();
        next
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
