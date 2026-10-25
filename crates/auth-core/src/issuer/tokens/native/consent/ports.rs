use super::{
    IssuerNativeAuthorizationDestination, IssuerNativeAuthorizationPreparation,
    IssuerNativeAuthorizationRequest,
};
use crate::{
    IssuerAuthority, IssuerAuthorizationDestination, IssuerAuthorizationRepository,
    IssuerConsentProof, IssuerNativeRefreshPolicy, Result, Verifier,
};
use async_trait::async_trait;
use uuid::Uuid;

/// Separate explicit operations; no default online port may approve offline consent.
#[async_trait]
pub trait IssuerNativeAuthorizationRepository: IssuerAuthorizationRepository {
    async fn load_issuer_native_refresh_policy(
        &self,
        authority: &IssuerAuthority,
        client: Uuid,
    ) -> Result<IssuerNativeRefreshPolicy>;
    async fn save_issuer_native_authorization(
        &self,
        request: &IssuerNativeAuthorizationRequest,
        current: Verifier,
        browser: Verifier,
        handle: Verifier,
    ) -> Result<IssuerNativeAuthorizationPreparation>;
    async fn preview_issuer_native_authorization(
        &self,
        proof: &IssuerConsentProof<'_>,
    ) -> Result<IssuerNativeAuthorizationDestination>;
    async fn approve_issuer_native_authorization(
        &self,
        proof: &IssuerConsentProof<'_>,
        code: Verifier,
    ) -> Result<IssuerNativeAuthorizationDestination>;
    /// Cancellation only reduces authority and must not require an enabled offline policy.
    async fn cancel_issuer_native_authorization(
        &self,
        proof: &IssuerConsentProof<'_>,
    ) -> Result<IssuerAuthorizationDestination>;
}
