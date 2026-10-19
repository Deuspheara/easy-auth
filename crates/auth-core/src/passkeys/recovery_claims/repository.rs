use super::PasskeyRecoveryClaimInfo;
use crate::{Result, Verifier};
use async_trait::async_trait;
use uuid::Uuid;

/// Browser verifier is a separate purpose-bound capability, never a session.
/// The public account identifier selects a candidate, not ownership authority.
pub struct PasskeyRecoveryClaimRequest {
    pub realm: Uuid,
    pub user_id: Uuid,
    pub rp_id: String,
    pub browser: Verifier,
    pub source: Verifier,
}

/// A fresh genuine passkey session selects its owner; no client owner field.
pub struct PasskeyRecoveryKeyCancellation {
    pub realm: Uuid,
    pub rp_id: String,
    pub session: Verifier,
    pub source: Verifier,
}

/// A reserved saved code may only deny its current claim, never resume from a
/// different browser, start another claim, bind a key or authenticate a session.
pub struct PasskeyRecoveryCodeCancellation {
    pub realm: Uuid,
    pub user_id: Uuid,
    pub rp_id: String,
    pub code: Verifier,
    pub source: Verifier,
}

#[async_trait]
pub trait PasskeyRecoveryClaimRepository: Send + Sync {
    async fn cancel_passkey_recovery_with_code(
        &self,
        request: &PasskeyRecoveryCodeCancellation,
    ) -> Result<()>;
    /// Admit before lookup. Reserve a current saved code once under owner/code
    /// locks, bind one claim to browser/version/RP and audit/notify atomically.
    /// A lost response may resume only the same live browser-bound claim, without
    /// minting a new grant, extending time, repeating audit or queuing another notice.
    async fn begin_passkey_recovery_claim(
        &self,
        request: &PasskeyRecoveryClaimRequest,
        candidate_id: Uuid,
        code: Verifier,
    ) -> Result<PasskeyRecoveryClaimInfo>;
    /// Recover a lost begin response with the already-bound browser capability,
    /// without re-verifying a code or depending on its account-attempt budget.
    async fn resume_passkey_recovery_claim(
        &self,
        request: &PasskeyRecoveryClaimRequest,
    ) -> Result<PasskeyRecoveryClaimInfo>;
    async fn passkey_recovery_claim(
        &self,
        request: &PasskeyRecoveryClaimRequest,
        id: Uuid,
    ) -> Result<PasskeyRecoveryClaimInfo>;
    /// Cancellation permanently invalidates the claim and never revives its code.
    async fn cancel_passkey_recovery_claim(
        &self,
        request: &PasskeyRecoveryClaimRequest,
        id: Uuid,
    ) -> Result<()>;
    /// Independent key-cancellation admission must remain available when an
    /// unauthenticated claimant has exhausted the claim's abuse budget.
    async fn cancel_passkey_recovery_with_key(
        &self,
        request: &PasskeyRecoveryKeyCancellation,
        id: Uuid,
    ) -> Result<()>;
}
