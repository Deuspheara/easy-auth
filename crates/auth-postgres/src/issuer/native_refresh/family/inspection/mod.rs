//! Read-only native access inspection with separate authenticated consumer policy.
mod state;
mod transaction;
use crate::Postgres;
use async_trait::async_trait;
use auth_core::{
    IssuerNativeAccessData, IssuerNativeIntrospectionRepository, IssuerTokenResult,
    IssuerTokenStatusRequest,
};

#[async_trait]
impl IssuerNativeIntrospectionRepository for Postgres {
    async fn introspect_issuer_native_access(
        &self,
        request: &IssuerTokenStatusRequest<'_>,
    ) -> IssuerTokenResult<Option<IssuerNativeAccessData>> {
        transaction::inspect(self, request).await
    }
}
