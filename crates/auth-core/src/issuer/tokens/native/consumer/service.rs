use super::{IssuerNativeAccessData, IssuerNativeActiveAccess};
use crate::{
    IssuerAuthority, IssuerAuthorization, IssuerAuthorizationRepository,
    IssuerClientAuthentication, IssuerPresentedToken, IssuerTokenError, IssuerTokenResult,
    IssuerTokenStatusRequest,
};
use async_trait::async_trait;
use std::{sync::Arc, time::Duration};

#[async_trait]
pub trait IssuerNativeIntrospectionRepository: IssuerAuthorizationRepository {
    /// Actual current confidential credentials must be compared even for unknown
    /// tokens. Missing/disabled audience permission returns no active claims;
    /// authentication and infrastructure faults remain errors.
    async fn introspect_issuer_native_access(
        &self,
        request: &IssuerTokenStatusRequest<'_>,
    ) -> IssuerTokenResult<Option<IssuerNativeAccessData>>;
}
const NATIVE_INTROSPECTION_TIMEOUT: Duration = Duration::from_secs(15);
pub struct IssuerNativeIntrospection {
    authorization: IssuerAuthorization,
    repository: Arc<dyn IssuerNativeIntrospectionRepository>,
}
impl IssuerNativeIntrospection {
    pub fn new(
        authority: IssuerAuthority,
        repository: Arc<dyn IssuerNativeIntrospectionRepository>,
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
    ) -> IssuerTokenResult<Option<IssuerNativeActiveAccess>> {
        tokio::time::timeout(NATIVE_INTROSPECTION_TIMEOUT, async {
            let consumer = self
                .authorization
                .client_for_token_operation(authentication, source)
                .await?;
            let request = IssuerTokenStatusRequest {
                authority: self.authority(),
                client: &consumer,
                authentication,
                token: token.verifier(),
            };
            request.validate_introspection()?;
            self.repository
                .introspect_issuer_native_access(&request)
                .await?
                .map(|data| {
                    IssuerNativeActiveAccess::from_repository(data, self.authority(), &consumer)
                })
                .transpose()
        })
        .await
        .map_err(|_| IssuerTokenError::Unavailable)?
    }
}
