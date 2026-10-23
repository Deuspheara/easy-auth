use super::{
    IssuerNativeCredentialRequest, IssuerNativeRefreshOutcome, IssuerNativeRefreshRepository,
    IssuerNativeRotatedTokens, IssuerNativeRotationRequest,
};
use crate::{
    IssuerAuthority, IssuerAuthorization, IssuerClientAuthentication, IssuerPresentedToken,
    IssuerTokenError, IssuerTokenResult, Secret,
};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

const NATIVE_OPERATION_TIMEOUT: Duration = Duration::from_secs(15);
pub struct IssuerNativeRefresh {
    authorization: IssuerAuthorization,
    repository: Arc<dyn IssuerNativeRefreshRepository>,
}
impl IssuerNativeRefresh {
    pub fn new(
        authority: IssuerAuthority,
        repository: Arc<dyn IssuerNativeRefreshRepository>,
    ) -> Self {
        Self {
            authorization: IssuerAuthorization::new(authority, repository.clone()),
            repository,
        }
    }
    pub fn authority(&self) -> &IssuerAuthority {
        self.authorization.authority()
    }
    pub async fn refresh(
        &self,
        authentication: &IssuerClientAuthentication,
        token: &IssuerPresentedToken,
        source: &str,
    ) -> IssuerTokenResult<IssuerNativeRotatedTokens> {
        tokio::time::timeout(NATIVE_OPERATION_TIMEOUT, async {
            let client = self
                .authorization
                .client_for_token_operation(authentication, source)
                .await?;
            let access = Secret::generate()?;
            let refresh = Secret::generate()?;
            let request = IssuerNativeRotationRequest {
                credential: IssuerNativeCredentialRequest {
                    authority: self.authority(),
                    client: &client,
                    authentication,
                    token: token.verifier(),
                },
                access_id: Uuid::new_v4(),
                access: access.verifier(),
                refresh: refresh.verifier(),
            };
            request.credential.validate_client()?;
            match self
                .repository
                .rotate_issuer_native_refresh(&request)
                .await?
            {
                IssuerNativeRefreshOutcome::Rotated(data) => IssuerNativeRotatedTokens::committed(
                    *data,
                    self.authority(),
                    &client,
                    access,
                    refresh,
                ),
                IssuerNativeRefreshOutcome::InvalidGrant
                | IssuerNativeRefreshOutcome::ReuseRevoked => Err(IssuerTokenError::InvalidGrant),
            }
        })
        .await
        .map_err(|_| IssuerTokenError::Unavailable)?
    }
    pub async fn revoke(
        &self,
        authentication: &IssuerClientAuthentication,
        token: &IssuerPresentedToken,
        source: &str,
    ) -> IssuerTokenResult<()> {
        tokio::time::timeout(NATIVE_OPERATION_TIMEOUT, async {
            let client = self
                .authorization
                .client_for_token_operation(authentication, source)
                .await?;
            self.revoke_admitted(&client, authentication, token).await
        })
        .await
        .map_err(|_| IssuerTokenError::Unavailable)?
    }
    pub(super) async fn revoke_admitted(
        &self,
        client: &crate::IssuerClientRegistration,
        authentication: &IssuerClientAuthentication,
        token: &IssuerPresentedToken,
    ) -> IssuerTokenResult<()> {
        let request = IssuerNativeCredentialRequest {
            authority: self.authority(),
            client,
            authentication,
            token: token.verifier(),
        };
        request.validate_client()?;
        self.repository.revoke_issuer_native_family(&request).await
    }
}
