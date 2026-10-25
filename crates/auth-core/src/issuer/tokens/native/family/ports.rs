use crate::{
    IssuerAuthority, IssuerAuthorizationRepository, IssuerClientAuthentication,
    IssuerClientRegistration, IssuerNativeRefreshPolicy, IssuerRedirectProfile, IssuerTokenError,
    IssuerTokenResult, Verifier,
};
use async_trait::async_trait;
use uuid::Uuid;

/// Trusted port data only. Hash possession must still match the exact current
/// scoped stored credential; no verifier representation is accepted over HTTP.
pub struct IssuerNativeCredentialRequest<'a> {
    pub authority: &'a IssuerAuthority,
    pub client: &'a IssuerClientRegistration,
    pub authentication: &'a IssuerClientAuthentication,
    pub token: Verifier,
}
impl IssuerNativeCredentialRequest<'_> {
    pub fn validate_client(&self) -> IssuerTokenResult<()> {
        if self.client.realm() != self.authority.realm()
            || self.client.redirect_profile() != IssuerRedirectProfile::NativeRefreshLoopback
        {
            return Err(IssuerTokenError::InvalidClient);
        }
        self.authentication
            .validate_for(self.client)
            .map_err(IssuerTokenError::client)
    }
}
pub struct IssuerNativeRotationRequest<'a> {
    pub credential: IssuerNativeCredentialRequest<'a>,
    pub access_id: Uuid,
    pub access: Verifier,
    pub refresh: Verifier,
}
/// Metadata for validating committed opaque credentials, not a local session or
/// independently authenticated identity/JWT. No owner/session/raw secret fields.
pub struct IssuerNativeRefreshData {
    pub policy: IssuerNativeRefreshPolicy,
    pub family_id: Uuid,
    pub subject: Uuid,
    pub generation: i64,
    pub prepared_at_us: i64,
    pub source_absolute_cap_us: i64,
    pub family_expires_at_us: i64,
    pub issued_at_us: i64,
    pub access_expires_at_us: i64,
    pub refresh_expires_at_us: i64,
    pub checked_at_us: i64,
}
/// Reuse is a committed revocation, not an error returned before rollback.
pub enum IssuerNativeRefreshOutcome {
    Rotated(Box<IssuerNativeRefreshData>),
    InvalidGrant,
    ReuseRevoked,
}
#[async_trait]
pub trait IssuerNativeRefreshRepository: IssuerAuthorizationRepository {
    async fn rotate_issuer_native_refresh(
        &self,
        request: &IssuerNativeRotationRequest<'_>,
    ) -> IssuerTokenResult<IssuerNativeRefreshOutcome>;
    async fn revoke_issuer_native_family(
        &self,
        request: &IssuerNativeCredentialRequest<'_>,
    ) -> IssuerTokenResult<()>;
}
