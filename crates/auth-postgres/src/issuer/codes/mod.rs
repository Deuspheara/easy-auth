mod admission;
mod clock;
mod decision;
mod preparation;
mod redemption;
mod state;

use crate::Postgres;
use async_trait::async_trait;
use auth_core::{
    IssuerAuthority, IssuerAuthorizationDestination, IssuerAuthorizationRepository,
    IssuerAuthorizationRequest, IssuerClientRegistration, IssuerCodeRedemption, IssuerConsentProof,
    IssuerGrantData, IssuerTokenResult, Result, Verifier,
};
use uuid::Uuid;

#[async_trait]
impl IssuerAuthorizationRepository for Postgres {
    async fn load_issuer_client(
        &self,
        realm: Uuid,
        client: Uuid,
    ) -> Result<IssuerClientRegistration> {
        Postgres::load_issuer_client(self, realm, client).await
    }
    async fn admit_issuer_redemption(
        &self,
        authority: &IssuerAuthority,
        source: Verifier,
    ) -> Result<()> {
        admission::admit(self, authority, source).await
    }
    async fn save_issuer_authorization(
        &self,
        request: &IssuerAuthorizationRequest,
        current: Verifier,
        browser: Verifier,
        handle: Verifier,
    ) -> Result<i64> {
        preparation::save(self, request, current, browser, handle).await
    }
    async fn preview_issuer_authorization(
        &self,
        proof: &IssuerConsentProof<'_>,
    ) -> Result<IssuerAuthorizationDestination> {
        decision::preview(self, proof).await
    }
    async fn approve_issuer_authorization(
        &self,
        proof: &IssuerConsentProof<'_>,
        code: Verifier,
    ) -> Result<IssuerAuthorizationDestination> {
        decision::approve(self, proof, code).await
    }
    async fn cancel_issuer_authorization(
        &self,
        proof: &IssuerConsentProof<'_>,
    ) -> Result<IssuerAuthorizationDestination> {
        decision::cancel(self, proof).await
    }
    async fn redeem_issuer_code(
        &self,
        request: &IssuerCodeRedemption<'_>,
    ) -> IssuerTokenResult<IssuerGrantData> {
        redemption::redeem(self, request).await
    }
}
