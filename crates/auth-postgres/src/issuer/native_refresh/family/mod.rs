//! Native credential rotation/revocation; no signature or cookie-idle extension.
mod revocation;
mod rotation;
mod state;
mod writing;

use crate::Postgres;
use async_trait::async_trait;
use auth_core::{
    IssuerNativeCredentialRequest, IssuerNativeRefreshOutcome, IssuerNativeRefreshRepository,
    IssuerNativeRotationRequest, IssuerTokenResult,
};

#[async_trait]
impl IssuerNativeRefreshRepository for Postgres {
    async fn rotate_issuer_native_refresh(
        &self,
        request: &IssuerNativeRotationRequest<'_>,
    ) -> IssuerTokenResult<IssuerNativeRefreshOutcome> {
        rotation::rotate(self, request).await
    }
    async fn revoke_issuer_native_family(
        &self,
        request: &IssuerNativeCredentialRequest<'_>,
    ) -> IssuerTokenResult<()> {
        revocation::revoke(self, request).await
    }
}
