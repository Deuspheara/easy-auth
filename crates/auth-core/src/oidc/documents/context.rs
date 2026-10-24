//! Borrowed persisted document context, never an authentication/identity proof.
use crate::{OAuthConnection, OidcConnectionRepository, Result};
#[derive(Clone, Copy)]
pub(in crate::oidc) struct DocumentContext<'a> {
    connection: &'a OAuthConnection,
    repository: &'a dyn OidcConnectionRepository,
}
impl<'a> DocumentContext<'a> {
    pub(super) fn provider(
        connection: &'a OAuthConnection,
        repository: &'a dyn OidcConnectionRepository,
    ) -> Self {
        Self {
            connection,
            repository,
        }
    }
    pub(super) fn configuration(&self) -> &OAuthConnection {
        self.connection
    }
    pub(super) async fn check(&self) -> Result<()> {
        self.repository.check_oidc_connection(self.connection).await
    }
}
