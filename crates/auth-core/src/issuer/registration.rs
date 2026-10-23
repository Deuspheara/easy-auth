use super::{native, redirects};
use crate::{Error, Result, Secret, Verifier};
use std::fmt;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssuerClientKind {
    Public,
    ConfidentialBasic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssuerRedirectProfile {
    WebExact,
    NativeLoopback,
}

/// Trusted outbound client metadata. Persist before use; neither this
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
    redirect_profile: IssuerRedirectProfile,
}
impl IssuerClientRegistration {
    pub fn public(realm: Uuid, client: Uuid, redirects: &[&str]) -> Result<Self> {
        Self::new(
            realm,
            client,
            redirects,
            None,
            IssuerRedirectProfile::WebExact,
        )
    }
    /// Public native application with literal loopback HTTP returns. Only the
    /// port varies; the later authorization code must retain the exact return.
    /// Subjects are isolated per registered native client, never by local IP.
    pub fn public_native_loopback(realm: Uuid, client: Uuid, redirects: &[&str]) -> Result<Self> {
        Self::new(
            realm,
            client,
            redirects,
            None,
            IssuerRedirectProfile::NativeLoopback,
        )
    }
    /// Keep the generated secret only at the trusted provisioning boundary.
    /// Only its irreversible verifier is retained by this registration.
    pub fn confidential(
        realm: Uuid,
        client: Uuid,
        redirects: &[&str],
        secret: &Secret,
    ) -> Result<Self> {
        Self::new(
            realm,
            client,
            redirects,
            Some(secret.verifier()),
            IssuerRedirectProfile::WebExact,
        )
    }
    /// Restore trusted persisted metadata without retaining a raw client secret.
    /// This is configuration, never authentication from a presented verifier.
    pub fn confidential_from_verifier(
        realm: Uuid,
        client: Uuid,
        redirects: &[&str],
        verifier: Verifier,
    ) -> Result<Self> {
        Self::new(
            realm,
            client,
            redirects,
            Some(verifier),
            IssuerRedirectProfile::WebExact,
        )
    }
    fn new(
        realm: Uuid,
        client: Uuid,
        redirects: &[&str],
        secret_verifier: Option<Verifier>,
        redirect_profile: IssuerRedirectProfile,
    ) -> Result<Self> {
        if realm.is_nil() || client.is_nil() {
            return Err(Error::InvalidInput);
        }
        let (redirects, sector) = match redirect_profile {
            IssuerRedirectProfile::WebExact => redirects::registration(redirects)?,
            IssuerRedirectProfile::NativeLoopback => {
                if secret_verifier.is_some() {
                    return Err(Error::InvalidInput);
                }
                (
                    native::registration(redirects)?,
                    format!("urn:easy-auth:native-client:{client}"),
                )
            }
        };
        Ok(Self {
            realm,
            client,
            revision: Uuid::new_v4(),
            redirects,
            sector,
            secret_verifier,
            redirect_profile,
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
    /// Web hostname sector or a separate per-native-client sector identifier.
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
    pub fn redirect_profile(&self) -> IssuerRedirectProfile {
        self.redirect_profile
    }
    /// Persistence configuration only; never log or treat it as a bearer secret.
    pub fn secret_verifier(&self) -> Option<Verifier> {
        self.secret_verifier
    }
    pub fn permits_redirect(&self, actual: &str) -> bool {
        match self.redirect_profile {
            IssuerRedirectProfile::WebExact => {
                self.redirects.iter().any(|registered| registered == actual)
            }
            IssuerRedirectProfile::NativeLoopback => native::permits(&self.redirects, actual),
        }
    }
    /// Repository replacement always allocates a new revision, even for stale input.
    pub fn reconfigured(&self) -> Self {
        let mut next = self.clone();
        next.revision = Uuid::new_v4();
        next
    }
    /// Restore a stored revision at a trusted persistence boundary. Current
    /// enabled full-definition checks are still mandatory on every operation.
    pub fn with_persisted_revision(mut self, revision: Uuid) -> Result<Self> {
        if revision.is_nil() {
            return Err(Error::InvalidInput);
        }
        self.revision = revision;
        Ok(self)
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
