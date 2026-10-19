use super::VerifiedPasskeySignupRegistration;
use crate::{
    PrivatePasskeyAuthentication, PrivatePasskeyRegistration, Result, StoredPasskey,
    VerifiedPasskeyAuthentication, Verifier,
};
use async_trait::async_trait;
use uuid::Uuid;

/// Server-created binding; no session or client-selected account participates.
pub struct PasskeySignupRequest {
    pub realm: Uuid,
    pub transaction: Uuid,
    pub browser: Verifier,
    pub source: Verifier,
}

pub struct PasskeySignupStart {
    pub request: PasskeySignupRequest,
    pub prospective_user: Uuid,
    pub rp_id: String,
    pub display_name: String,
    pub state: PrivatePasskeyRegistration,
}

/// Trusted pending context, not a persisted account or an authentication result.
pub struct PasskeySignupRegistrationContext {
    pub prospective_user: Uuid,
    pub state: PrivatePasskeyRegistration,
}

#[async_trait]
pub trait PasskeySignupRepository: Send + Sync {
    /// Admit and bound pending resources; do not create a durable user or credential.
    async fn save_signup(&self, pending: PasskeySignupStart) -> Result<()>;
    /// Commit admission before loading fresh browser/realm/RP/stage-bound state.
    async fn load_signup_registration(
        &self,
        request: &PasskeySignupRequest,
        rp_id: &str,
    ) -> Result<PasskeySignupRegistrationContext>;
    /// One winner advances the exact verified registration; no session/account yet.
    async fn advance_signup(
        &self,
        request: &PasskeySignupRequest,
        registration: VerifiedPasskeySignupRegistration,
    ) -> Result<()>;
    async fn load_signup_authentication(
        &self,
        request: &PasskeySignupRequest,
        rp_id: &str,
    ) -> Result<(PrivatePasskeyAuthentication, StoredPasskey)>;
    /// Recheck exact snapshots and expiry after every wait, then atomically create
    /// the user/key/session/audit and consume the pending signup.
    async fn commit_signup(
        &self,
        request: &PasskeySignupRequest,
        proof: VerifiedPasskeyAuthentication,
        session: Verifier,
    ) -> Result<()>;
}
