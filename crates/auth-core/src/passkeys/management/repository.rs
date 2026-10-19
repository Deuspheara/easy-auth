use super::PasskeyInfo;
use crate::{Result, Verifier};
use async_trait::async_trait;
use uuid::Uuid;

/// Trusted composition supplies realm/RP; the adapter revalidates owner and method.
/// No Debug/Serialize: verifiers must not enter logs or HTTP responses.
pub struct PasskeyManagementRequest {
    pub realm: Uuid,
    pub session: Verifier,
    pub rp_id: String,
    pub source: Verifier,
}

#[async_trait]
pub trait PasskeyManagementRepository: Send + Sync {
    async fn list_passkeys(&self, request: &PasskeyManagementRequest) -> Result<Vec<PasskeyInfo>>;
    async fn rename_passkey(
        &self,
        request: &PasskeyManagementRequest,
        id: Uuid,
        version: Uuid,
        label: &str,
    ) -> Result<Uuid>;
    /// Owner-serialized last-proven-key guard; revoke sessions/proofs, audit and notify atomically.
    async fn remove_passkey(
        &self,
        request: &PasskeyManagementRequest,
        id: Uuid,
        version: Uuid,
    ) -> Result<()>;
}
