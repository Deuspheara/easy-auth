use crate::{PrivatePasskeyAuthentication, Result, VerifiedPasskey};
use std::fmt;
use uuid::Uuid;

/// Constructed only after this use case verifies the private registration.
pub struct VerifiedPasskeyRecoveryRegistration {
    pub(super) owner: Uuid,
    pub(super) expected: Vec<u8>,
    pub(super) candidate: VerifiedPasskey,
    pub(super) assertion: PrivatePasskeyAuthentication,
}
impl VerifiedPasskeyRecoveryRegistration {
    pub fn realm(&self) -> Uuid {
        self.assertion.realm()
    }
    pub fn user_id(&self) -> Uuid {
        self.owner
    }
    pub fn rp_id(&self) -> &str {
        self.candidate.rp_id()
    }
    pub fn credential_id(&self) -> &[u8] {
        self.candidate.credential_id()
    }
    pub fn expected_registration_for_database(&self) -> &[u8] {
        &self.expected
    }
    pub fn credential_for_database(&self) -> Result<Vec<u8>> {
        self.candidate.encode_for_database()
    }
    pub fn assertion_for_database(&self) -> Result<Vec<u8>> {
        self.assertion.encode_for_database()
    }
}
impl fmt::Debug for VerifiedPasskeyRecoveryRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedPasskeyRecoveryRegistration([REDACTED])")
    }
}
