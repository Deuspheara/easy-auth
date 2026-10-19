use super::VerifiedPasskeyRecoveryRegistration;
use crate::{
    PasskeyRecoveryClaimRequest, PrivatePasskeyAuthentication, PrivatePasskeyRegistration, Result,
    StoredPasskey, VerifiedPasskeyAuthentication, Verifier,
};
use async_trait::async_trait;
use uuid::Uuid;

pub struct PasskeyRecoveryReplacementRequest {
    pub claim: PasskeyRecoveryClaimRequest,
    pub claim_id: Uuid,
    pub transaction: Uuid,
}

pub struct PasskeyRecoveryReplacementStart {
    pub request: PasskeyRecoveryReplacementRequest,
    pub state: PrivatePasskeyRegistration,
}

/// Options/state loads admit before lookup. Every stage locks owner then current
/// claim and verifies delay/receipt/generation/browser. Verified transitions recheck
/// exact snapshots after those admitted loads; private candidates never authenticate.
#[async_trait]
pub trait PasskeyRecoveryReplacementRepository: Send + Sync {
    async fn save_recovery_replacement(
        &self,
        pending: PasskeyRecoveryReplacementStart,
    ) -> Result<()>;
    async fn load_recovery_registration(
        &self,
        request: &PasskeyRecoveryReplacementRequest,
    ) -> Result<PrivatePasskeyRegistration>;
    async fn advance_recovery_replacement(
        &self,
        request: &PasskeyRecoveryReplacementRequest,
        registration: VerifiedPasskeyRecoveryRegistration,
    ) -> Result<()>;
    async fn load_recovery_assertion(
        &self,
        request: &PasskeyRecoveryReplacementRequest,
    ) -> Result<(PrivatePasskeyAuthentication, StoredPasskey)>;
    /// Exact snapshots, one winner, original deadlines through final writes.
    /// A lost response is resolved by normal sign-in with the installed key;
    /// replay never retrieves or mints another unrestricted session.
    async fn commit_recovery_replacement(
        &self,
        request: &PasskeyRecoveryReplacementRequest,
        proof: VerifiedPasskeyAuthentication,
        session: Verifier,
    ) -> Result<()>;
}
