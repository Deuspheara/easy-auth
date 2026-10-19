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
    /// Lock the exact live/fresh owner/session and call the shared enrollment
    /// authority policy using its stored method and realm-wide key presence.
    /// Known mailbox/password methods bootstrap only the first key; unknown
    /// methods never bind a key. Finish-time checks must repeat this decision.
    async fn enrollment_context(
        &self,
        realm: Uuid,
        session: Verifier,
        rp_id: &str,
    ) -> Result<PasskeyEnrollmentContext>;
    /// Revalidate method/ownership under locks, enforce admission, persist private
    /// state and recheck the original authentication deadline after all writes.
    async fn save_enrollment(&self, pending: PasskeyEnrollmentStart) -> Result<()>;
    /// Admit verification and load only a fresh, appropriately authenticated,
    /// session/browser/realm-bound unexpired ceremony; cap the final read/admission.
    async fn load_enrollment(
        &self,
        request: &PasskeyEnrollmentRequest,
    ) -> Result<PrivatePasskeyRegistration>;
    /// Recheck the exact verified state, ownership, freshness, expiry and limits under locks;
    /// repeat additional-enrollment authority, consume, insert the RP-unique key
    /// and record audit atomically. Original proof/session deadlines cap all final
    /// writes, including proof consumption itself.
    async fn commit_enrollment(
        &self,
        request: &PasskeyEnrollmentRequest,
        expected_state: &[u8],
        credential: VerifiedPasskey,
    ) -> Result<Uuid>;
}
