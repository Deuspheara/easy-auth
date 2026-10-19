use crate::{Result, Verifier};
use async_trait::async_trait;
use uuid::Uuid;

/// Trusted composition supplies realm/RP; verifiers must never be logged.
pub struct PasskeyRecoverySetupRequest {
    pub realm: Uuid,
    pub session: Verifier,
    pub rp_id: String,
    pub source: Verifier,
}

#[async_trait]
pub trait PasskeyRecoverySetupRepository: Send + Sync {
    /// Require genuine fresh passkey authority under owner/session locks. Replace
    /// only this owner's pending setup, retaining any previously confirmed code.
    async fn prepare_passkey_recovery_code(
        &self,
        request: &PasskeyRecoverySetupRequest,
        id: Uuid,
        code: Verifier,
    ) -> Result<()>;

    /// Revalidate exact owner/session/RP, method, pending ID/verifier and original
    /// deadlines. Replace active code, consume pending setup, audit and queue an
    /// existing verified-contact notice atomically. No session or policy change.
    async fn confirm_passkey_recovery_code(
        &self,
        request: &PasskeyRecoverySetupRequest,
        id: Uuid,
        code: Verifier,
    ) -> Result<()>;
}
