use super::{PrivatePasskeyAuthentication, StoredPasskey, VerifiedPasskeyAuthentication};
use crate::{Result, Verifier};
use async_trait::async_trait;
use uuid::Uuid;

/// Server-owned ceremony binding. Never serialize or log its verifier fields.
pub struct PasskeyAuthenticationRequest {
    pub realm: Uuid,
    pub transaction: Uuid,
    pub browser: Verifier,
    pub source: Verifier,
}

pub struct PasskeyAuthenticationStart {
    pub request: PasskeyAuthenticationRequest,
    pub rp_id: String,
    pub state: PrivatePasskeyAuthentication,
}

#[async_trait]
pub trait PasskeyAuthenticationRepository: Send + Sync {
    /// Persist admission before lookup. Account ID is a lookup hint, never proof.
    /// None prepares conditional discovery; account selection belongs to the caller.
    async fn prepare_authentication(
        &self,
        request: &PasskeyAuthenticationRequest,
        rp_id: &str,
        owner: Option<Uuid>,
    ) -> Result<Vec<StoredPasskey>>;
    async fn save_authentication(&self, pending: PasskeyAuthenticationStart) -> Result<()>;
    /// Spend admission even on invalid IDs or binding, then load a live ceremony and
    /// credential scoped to the trusted realm/RP. This does not authenticate its owner.
    async fn load_authentication(
        &self,
        request: &PasskeyAuthenticationRequest,
        rp_id: &str,
        credential_id: &[u8],
    ) -> Result<(PrivatePasskeyAuthentication, StoredPasskey)>;
    /// Lock owner before credential/ceremony; recheck the exact proof snapshots and
    /// expiry, then consume/update/issue/audit in one transaction. No session on failure.
    async fn commit_authentication(
        &self,
        request: &PasskeyAuthenticationRequest,
        proof: VerifiedPasskeyAuthentication,
        session: Verifier,
    ) -> Result<()>;
}
