use super::IssuerAccessData;
use crate::{
    IssuerAuthority, IssuerAuthorizationRepository, IssuerClientAuthentication, IssuerClientKind,
    IssuerClientRegistration, IssuerTokenError, IssuerTokenResult, Verifier,
};
use async_trait::async_trait;

/// Request data only. Current credential/definition comparison must still happen
/// inside the operation's transaction, even when the token cannot be found.
pub struct IssuerTokenStatusRequest<'a> {
    pub authority: &'a IssuerAuthority,
    pub client: &'a IssuerClientRegistration,
    pub authentication: &'a IssuerClientAuthentication,
    pub token: Verifier,
}
impl IssuerTokenStatusRequest<'_> {
    pub fn validate_client(&self) -> IssuerTokenResult<()> {
        if self.client.realm() != self.authority.realm() {
            return Err(IssuerTokenError::InvalidClient);
        }
        self.authentication
            .validate_for(self.client)
            .map_err(IssuerTokenError::client)
    }
    /// Public identification is insufficient for introspection. The owning
    /// repository must compare actual credentials and enforce its audience policy;
    /// this method alone grants no cross-client inspection permission.
    pub fn validate_introspection(&self) -> IssuerTokenResult<()> {
        self.validate_client()?;
        if self.client.kind() != IssuerClientKind::ConfidentialBasic {
            return Err(IssuerTokenError::InvalidClient);
        }
        Ok(())
    }
}
#[async_trait]
pub trait IssuerTokenStatusRepository: IssuerAuthorizationRepository {
    /// Return None for unknown, foreign, revoked or inactive tokens. A current
    /// client-authentication or storage failure must never become inactive success.
    async fn introspect_issuer_access(
        &self,
        request: &IssuerTokenStatusRequest<'_>,
    ) -> IssuerTokenResult<Option<IssuerAccessData>>;
    /// Possession authorizes only matching realm/issuer/client token revocation.
    /// Unknown/foreign/already-revoked input is an indistinguishable success.
    async fn revoke_issuer_access(
        &self,
        request: &IssuerTokenStatusRequest<'_>,
    ) -> IssuerTokenResult<()>;
}
