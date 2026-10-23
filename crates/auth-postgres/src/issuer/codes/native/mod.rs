//! Explicit offline consent. Default online code paths continue refusing it.
mod decision;
pub(super) mod preparation;
mod state;

use crate::Postgres;
use async_trait::async_trait;
use auth_core::{
    IssuerAuthority, IssuerAuthorizationDestination, IssuerConsentProof,
    IssuerNativeAuthorizationDestination, IssuerNativeAuthorizationPreparation,
    IssuerNativeAuthorizationRepository, IssuerNativeAuthorizationRequest,
    IssuerNativeRefreshPolicy, Result, Verifier,
};
use uuid::Uuid;

#[async_trait]
impl IssuerNativeAuthorizationRepository for Postgres {
    async fn load_issuer_native_refresh_policy(
        &self,
        authority: &IssuerAuthority,
        client: Uuid,
    ) -> Result<IssuerNativeRefreshPolicy> {
        Postgres::load_issuer_native_refresh_policy(self, authority, client).await
    }
    async fn save_issuer_native_authorization(
        &self,
        request: &IssuerNativeAuthorizationRequest,
        current: Verifier,
        browser: Verifier,
        handle: Verifier,
    ) -> Result<IssuerNativeAuthorizationPreparation> {
        super::preparation::save_native(self, request, current, browser, handle).await
    }
    async fn preview_issuer_native_authorization(
        &self,
        proof: &IssuerConsentProof<'_>,
    ) -> Result<IssuerNativeAuthorizationDestination> {
        decision::preview(self, proof).await
    }
    async fn approve_issuer_native_authorization(
        &self,
        proof: &IssuerConsentProof<'_>,
        code: Verifier,
    ) -> Result<IssuerNativeAuthorizationDestination> {
        decision::approve(self, proof, code).await
    }
    async fn cancel_issuer_native_authorization(
        &self,
        proof: &IssuerConsentProof<'_>,
    ) -> Result<IssuerAuthorizationDestination> {
        decision::cancel(self, proof).await
    }
}
