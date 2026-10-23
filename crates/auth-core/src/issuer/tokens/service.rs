use super::{
    IssuerActiveAccess, IssuerPresentedToken, IssuerTokenStatusRepository, IssuerTokenStatusRequest,
};
use crate::{
    IssuerAuthority, IssuerAuthorization, IssuerClientAuthentication, IssuerTokenError,
    IssuerTokenResult,
};
use std::{sync::Arc, time::Duration};

const TOKEN_STATUS_TIMEOUT: Duration = Duration::from_secs(15);
pub struct IssuerTokenManagement {
    authorization: IssuerAuthorization,
    repository: Arc<dyn IssuerTokenStatusRepository>,
}
impl IssuerTokenManagement {
    pub fn new(
        authority: IssuerAuthority,
        repository: Arc<dyn IssuerTokenStatusRepository>,
    ) -> Self {
        Self {
            authorization: IssuerAuthorization::new(authority, repository.clone()),
            repository,
        }
    }
    pub fn authority(&self) -> &IssuerAuthority {
        self.authorization.authority()
    }
    pub async fn introspect_access(
        &self,
        authentication: &IssuerClientAuthentication,
        token: &IssuerPresentedToken,
        source: &str,
    ) -> IssuerTokenResult<Option<IssuerActiveAccess>> {
        tokio::time::timeout(TOKEN_STATUS_TIMEOUT, async {
            let client = self
                .authorization
                .client_for_token_operation(authentication, source)
                .await?;
            let request = IssuerTokenStatusRequest {
                authority: self.authority(),
                client: &client,
                authentication,
                token: token.verifier(),
            };
            request.validate_introspection()?;
            self.repository
                .introspect_issuer_access(&request)
                .await?
                .map(|data| IssuerActiveAccess::from_repository(data, self.authority(), &client))
                .transpose()
        })
        .await
        .map_err(|_| IssuerTokenError::Unavailable)?
    }
    pub async fn revoke_access(
        &self,
        authentication: &IssuerClientAuthentication,
        token: &IssuerPresentedToken,
        source: &str,
    ) -> IssuerTokenResult<()> {
        tokio::time::timeout(TOKEN_STATUS_TIMEOUT, async {
            let client = self
                .authorization
                .client_for_token_operation(authentication, source)
                .await?;
            self.revoke_admitted(&client, authentication, token).await
        })
        .await
        .map_err(|_| IssuerTokenError::Unavailable)?
    }
    pub(in crate::issuer::tokens) async fn revoke_admitted(
        &self,
        client: &crate::IssuerClientRegistration,
        authentication: &IssuerClientAuthentication,
        token: &IssuerPresentedToken,
    ) -> IssuerTokenResult<()> {
        self.repository
            .revoke_issuer_access(&IssuerTokenStatusRequest {
                authority: self.authority(),
                client,
                authentication,
                token: token.verifier(),
            })
            .await
    }
}
