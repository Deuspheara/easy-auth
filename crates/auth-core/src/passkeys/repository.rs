use super::{PrivatePasskeyRegistration, VerifiedPasskey};
use crate::{Result, Verifier};
use async_trait::async_trait;
use uuid::Uuid;

/// Trusted adapter context, never a client-selected owner.
pub struct PasskeyEnrollmentContext {
    pub user_id: Uuid,
    pub account_name: String,
    pub excluded_credentials: Vec<Vec<u8>>,
}

/// Server-constructed binding. Source is for admission, not an IP-based authentication factor.
/// No Debug/Serialize: session and browser verifiers must not enter logs or responses.
pub struct PasskeyEnrollmentRequest {
    pub realm: Uuid,
    pub session: Verifier,
    pub browser: Verifier,
    pub source: Verifier,
    pub transaction: Uuid,
}

pub struct PasskeyEnrollmentStart {
    pub request: PasskeyEnrollmentRequest,
    pub user_id: Uuid,
    pub rp_id: String,
    pub label: String,
    pub state: PrivatePasskeyRegistration,
}

#[async_trait]
pub trait PasskeyRepository: Send + Sync {
    async fn enrollment_context(
        &self,
        realm: Uuid,
        session: Verifier,
        rp_id: &str,
    ) -> Result<PasskeyEnrollmentContext>;
    /// Revalidate fresh ownership, enforce admission and persist private state with database expiry.
    async fn save_enrollment(&self, pending: PasskeyEnrollmentStart) -> Result<()>;
    /// Admit verification and load only a fresh, session/browser/realm-bound unexpired ceremony.
    async fn load_enrollment(
        &self,
        request: &PasskeyEnrollmentRequest,
    ) -> Result<PrivatePasskeyRegistration>;
    /// Recheck the exact verified state, ownership, freshness, expiry and limits under locks;
    /// consume, insert the RP-unique credential and record audit in one transaction.
    async fn commit_enrollment(
        &self,
        request: &PasskeyEnrollmentRequest,
        expected_state: &[u8],
        credential: VerifiedPasskey,
    ) -> Result<Uuid>;
}
