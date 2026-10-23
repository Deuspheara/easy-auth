use super::{
    IssuerAuthority, IssuerAuthorizationDestination, IssuerAuthorizationRequest, IssuerGrantData,
    IssuerTokenResult,
};
use crate::{IssuerClientAuthentication, IssuerClientRegistration, Result, Verifier};
use async_trait::async_trait;
use uuid::Uuid;

/// Repository-only verifier bindings. These fields grant nothing without the
/// exact fresh initiating session, owner and pending record in the transaction.
pub struct IssuerConsentProof<'a> {
    pub authorization: Uuid,
    pub authority: &'a IssuerAuthority,
    pub current: Verifier,
    pub browser: Verifier,
    pub handle: Verifier,
}
pub struct IssuerCodeRedemption<'a> {
    pub authority: &'a IssuerAuthority,
    pub client: &'a IssuerClientRegistration,
    pub authentication: &'a IssuerClientAuthentication,
    pub code: Verifier,
    pub redirect_uri: &'a str,
    pub pkce: Verifier,
}
#[async_trait]
pub trait IssuerAuthorizationRepository: Send + Sync {
    async fn load_issuer_client(
        &self,
        realm: Uuid,
        client: Uuid,
    ) -> Result<IssuerClientRegistration>;
    /// Independent committed abuse budget, even for unknown/wrong clients. The
    /// source comes from trusted network transport, never a browser identifier.
    async fn admit_issuer_redemption(
        &self,
        authority: &IssuerAuthority,
        source: Verifier,
    ) -> Result<()>;
    async fn save_issuer_authorization(
        &self,
        request: &IssuerAuthorizationRequest,
        current: Verifier,
        browser: Verifier,
        handle: Verifier,
    ) -> Result<i64>;
    /// Revalidate existing pending consent for display only, without allocating
    /// a subject/code or changing its original lifetime.
    async fn preview_issuer_authorization(
        &self,
        proof: &IssuerConsentProof<'_>,
    ) -> Result<IssuerAuthorizationDestination>;
    async fn approve_issuer_authorization(
        &self,
        proof: &IssuerConsentProof<'_>,
        code: Verifier,
    ) -> Result<IssuerAuthorizationDestination>;
    async fn cancel_issuer_authorization(
        &self,
        proof: &IssuerConsentProof<'_>,
    ) -> Result<IssuerAuthorizationDestination>;
    /// Exact current client/credential, original owner/session/source, actual URI,
    /// S256, original caps, audit and one-use transition must commit atomically.
    async fn redeem_issuer_code(
        &self,
        request: &IssuerCodeRedemption<'_>,
    ) -> IssuerTokenResult<IssuerGrantData>;
}
