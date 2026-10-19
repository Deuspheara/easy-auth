use crate::{PrivatePasskeyAuthentication, Result, VerifiedPasskey};
use std::fmt;
use uuid::Uuid;

/// Only the signup use case constructs this bound transition; it is not authentication.
pub struct VerifiedPasskeySignupRegistration {
    pub(super) owner: Uuid,
    pub(super) expected_state: Vec<u8>,
    pub(super) candidate: VerifiedPasskey,
    pub(super) assertion: PrivatePasskeyAuthentication,
}

impl VerifiedPasskeySignupRegistration {
    pub fn realm(&self) -> Uuid {
        self.assertion.realm()
    }
    pub fn prospective_user(&self) -> Uuid {
        self.owner
    }
    pub fn rp_id(&self) -> &str {
        self.candidate.rp_id()
    }
    pub fn credential_id(&self) -> &[u8] {
        self.candidate.credential_id()
    }
    pub fn expected_registration_for_database(&self) -> &[u8] {
        &self.expected_state
    }
    pub fn credential_for_database(&self) -> Result<Vec<u8>> {
        self.candidate.encode_for_database()
    }
    pub fn assertion_for_database(&self) -> Result<Vec<u8>> {
        self.assertion.encode_for_database()
    }
}

impl fmt::Debug for VerifiedPasskeySignupRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedPasskeySignupRegistration([REDACTED])")
    }
}
