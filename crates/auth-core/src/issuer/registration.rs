use super::redirects;
use crate::{Error, Result, Secret, Verifier};
use std::fmt;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssuerClientKind {
    Public,
    ConfidentialBasic,
}

/// Trusted outbound HTTPS web-client metadata. Persist before use; neither this
/// value nor subject allocation proves consent, client authentication or a session.
#[derive(Clone, Eq, PartialEq)]
#[must_use]
pub struct IssuerClientRegistration {
    realm: Uuid,
    client: Uuid,
    revision: Uuid,
    redirects: Vec<String>,
    sector: String,
    secret_verifier: Option<Verifier>,
}
impl IssuerClientRegistration {
    pub fn public(realm: Uuid, client: Uuid, redirects: &[&str]) -> Result<Self> {
        Self::new(realm, client, redirects, None)
    }
    /// Keep the generated secret only at the trusted provisioning boundary.
    /// Only its irreversible verifier is retained by this registration.
    pub fn confidential(
        realm: Uuid,
        client: Uuid,
        redirects: &[&str],
        secret: &Secret,
    ) -> Result<Self> {
        Self::new(realm, client, redirects, Some(secret.verifier()))
    }
    fn new(
        realm: Uuid,
        client: Uuid,
        redirects: &[&str],
        secret_verifier: Option<Verifier>,
    ) -> Result<Self> {
        if realm.is_nil() || client.is_nil() {
            return Err(Error::InvalidInput);
        }
        let (redirects, sector) = redirects::registration(redirects)?;
        Ok(Self {
            realm,
            client,
            revision: Uuid::new_v4(),
            redirects,
            sector,
            secret_verifier,
        })
    }
    pub fn realm(&self) -> Uuid {
        self.realm
    }
    pub fn client(&self) -> Uuid {
        self.client
    }
    pub fn revision(&self) -> Uuid {
        self.revision
    }
    pub fn redirects(&self) -> &[String] {
        &self.redirects
    }
    /// Hostname sector shared by trusted clients under the same host control.
    pub fn sector(&self) -> &str {
        &self.sector
    }
    pub fn kind(&self) -> IssuerClientKind {
        if self.secret_verifier.is_some() {
            IssuerClientKind::ConfidentialBasic
        } else {
            IssuerClientKind::Public
        }
    }
    /// Persistence configuration only; never log or treat it as a bearer secret.
    pub fn secret_verifier(&self) -> Option<Verifier> {
        self.secret_verifier
    }
    pub fn permits_redirect(&self, actual: &str) -> bool {
        self.redirects.iter().any(|registered| registered == actual)
    }
    /// Repository replacement always allocates a new revision, even for stale input.
    pub fn reconfigured(&self) -> Self {
        let mut next = self.clone();
        next.revision = Uuid::new_v4();
        next
    }
}
impl fmt::Debug for IssuerClientRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuerClientRegistration")
            .field("realm", &self.realm)
            .field("client", &self.client)
            .field("revision", &self.revision)
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}
