//! Read context only, never an identity/session or consumed-exchange proof.
use crate::oidc::{metadata, policy::Policy};
use crate::{OAuthConnection, OidcConnectionRepository, OidcDiscovery, OidcHttpResponse, Result};
#[derive(Clone, Copy)]
pub(in crate::oidc) enum DocumentContext<'a> {
    Provider {
        connection: &'a OAuthConnection,
        repository: &'a dyn OidcConnectionRepository,
    },
    #[cfg(feature = "oidc-client")]
    Client { issuer: &'a str },
}
impl<'a> DocumentContext<'a> {
    pub(super) fn provider(
        connection: &'a OAuthConnection,
        repository: &'a dyn OidcConnectionRepository,
    ) -> Self {
        Self::Provider {
            connection,
            repository,
        }
    }
    #[cfg(feature = "oidc-client")]
    pub(in crate::oidc) fn client(issuer: &'a str) -> Self {
        Self::Client { issuer }
    }
    pub(super) fn decode(
        self,
        response: OidcHttpResponse,
        policy: &Policy,
    ) -> Result<OidcDiscovery> {
        match self {
            Self::Provider { connection, .. } => metadata::discovery(response, connection, policy),
            #[cfg(feature = "oidc-client")]
            Self::Client { issuer } => metadata::discovery_expected(response, issuer, true, policy),
        }
    }
    pub(super) async fn check(&self) -> Result<()> {
        match self {
            Self::Provider {
                connection,
                repository,
            } => repository.check_oidc_connection(connection).await,
            // The caller owns one immutable client configuration and its cache.
            // This branch is not reachable through the provider-document facade.
            #[cfg(feature = "oidc-client")]
            Self::Client { .. } => Ok(()),
        }
    }
}
