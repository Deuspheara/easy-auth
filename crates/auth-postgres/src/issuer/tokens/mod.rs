mod introspection;
mod revocation;
mod state;

use crate::Postgres;
use async_trait::async_trait;
use auth_core::{
    IssuerAccessData, IssuerTokenResult, IssuerTokenStatusRepository, IssuerTokenStatusRequest,
};

impl Postgres {
    pub async fn introspect_issuer_access(
        &self,
        request: &IssuerTokenStatusRequest<'_>,
    ) -> IssuerTokenResult<Option<IssuerAccessData>> {
        introspection::inspect(self, request).await
    }
    pub async fn revoke_issuer_access(
        &self,
        request: &IssuerTokenStatusRequest<'_>,
    ) -> IssuerTokenResult<()> {
        revocation::revoke(self, request).await
    }
}
#[async_trait]
impl IssuerTokenStatusRepository for Postgres {
    async fn introspect_issuer_access(
        &self,
        request: &IssuerTokenStatusRequest<'_>,
    ) -> IssuerTokenResult<Option<IssuerAccessData>> {
        Postgres::introspect_issuer_access(self, request).await
    }
    async fn revoke_issuer_access(
        &self,
        request: &IssuerTokenStatusRequest<'_>,
    ) -> IssuerTokenResult<()> {
        Postgres::revoke_issuer_access(self, request).await
    }
}
