mod context;
mod retrieval;
#[cfg(feature = "oidc-verification")]
use super::OidcTarget;
use super::{OidcConnectionRepository, OidcDiscovery, OidcHttp, OidcJwksDocument, policy::Policy};
use crate::{OAuthConnection, Result};
pub(super) use context::DocumentContext;
pub(super) use retrieval::DocumentRetrieval;
use std::sync::Arc;
#[cfg(feature = "oidc-verification")]
use url::Url;

/// One immutable realm/connection/client/revision and two bounded cache slots.
/// No caller-supplied URL, token `jku`, provider identity or session is accepted.
pub struct OidcDocuments {
    connection: OAuthConnection,
    repository: Arc<dyn OidcConnectionRepository>,
    retrieval: DocumentRetrieval,
}
impl OidcDocuments {
    /// Validate trusted URL/egress metadata before provisioning or allocating.
    /// This performs no I/O and establishes no current authority.
    pub fn validate_configuration(connection: &OAuthConnection, origins: &[&str]) -> Result<()> {
        Policy::new(connection, origins).map(|_| ())
    }
    #[cfg(feature = "oidc-verification")]
    pub(super) fn connection(&self) -> &OAuthConnection {
        &self.connection
    }
    pub fn new(
        connection: OAuthConnection,
        origins: &[&str],
        repository: Arc<dyn OidcConnectionRepository>,
        http: Arc<dyn OidcHttp>,
    ) -> Result<Self> {
        let policy = Policy::new(&connection, origins)?;
        Ok(Self {
            connection,
            repository,
            retrieval: DocumentRetrieval::new(policy, http),
        })
    }
    fn context(&self) -> DocumentContext<'_> {
        DocumentContext::provider(&self.connection, self.repository.as_ref())
    }
    pub async fn discovery(&self) -> Result<OidcDiscovery> {
        self.retrieval.discovery(self.context()).await
    }
    #[cfg(feature = "oidc-verification")]
    pub(super) async fn discovery_when_admitted(&self) -> Result<OidcDiscovery> {
        self.retrieval.discovery_when_admitted(self.context()).await
    }
    /// Bounded public-key envelope, not a verified key/signature/identity proof.
    pub async fn jwks(&self) -> Result<OidcJwksDocument> {
        self.retrieval.jwks(self.context()).await
    }
    /// One bounded refresh of an observed snapshot; no signature is verified.
    pub async fn refresh_jwks(&self, observed: &OidcJwksDocument) -> Result<OidcJwksDocument> {
        self.retrieval.refresh_jwks(self.context(), observed).await
    }
    #[cfg(feature = "oidc-verification")]
    pub(super) async fn keys_from_discovery(
        &self,
        discovery: &OidcDiscovery,
        observed: Option<&OidcJwksDocument>,
    ) -> Result<OidcJwksDocument> {
        self.retrieval
            .keys_from_discovery(self.context(), discovery, observed)
            .await
    }
    #[cfg(feature = "oidc-verification")]
    pub(super) async fn keys_when_admitted(
        &self,
        discovery: &OidcDiscovery,
    ) -> Result<OidcJwksDocument> {
        self.retrieval
            .keys_when_admitted(self.context(), discovery)
            .await
    }
    #[cfg(feature = "oidc-verification")]
    pub(super) async fn resolve_target(&self, url: Url) -> Result<OidcTarget> {
        self.retrieval.resolve_target(url).await
    }
}
