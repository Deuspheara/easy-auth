use super::timing;
use saml_rs::{ReplayCache, ReplayKey, SamlError};
use sha2::{Digest, Sha256};
use std::{fmt, time::SystemTime};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SamlReplayKind {
    Response,
    Assertion,
}

/// Authenticated replay reservation awaiting an atomic durable commit. The hash
/// contains no raw identifier. Its namespace must survive registration rotation.
pub struct SamlReplayRecord {
    pub(super) kind: SamlReplayKind,
    pub(super) hash: [u8; 32],
    pub(super) retain_until_us: i64,
}
impl SamlReplayRecord {
    pub fn kind(&self) -> SamlReplayKind {
        self.kind
    }
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }
    pub fn retain_until_us(&self) -> i64 {
        self.retain_until_us
    }
}
impl fmt::Debug for SamlReplayRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SamlReplayRecord([REDACTED; not committed])")
    }
}

#[derive(Default)]
pub(super) struct Reservations(pub Vec<SamlReplayRecord>);
impl ReplayCache for Reservations {
    fn check_and_store(&mut self, key: ReplayKey, expires_at: SystemTime) -> Result<(), SamlError> {
        let kind = match key {
            ReplayKey::ResponseId(_) => SamlReplayKind::Response,
            ReplayKey::AssertionId(_) => SamlReplayKind::Assertion,
            _ => return Err(invalid()),
        };
        let hash: [u8; 32] = Sha256::digest(key.value().as_bytes()).into();
        if self.0.len() >= 2 || self.0.iter().any(|r| r.hash == hash || r.kind == kind) {
            return Err(invalid());
        }
        self.0.push(SamlReplayRecord {
            kind,
            hash,
            retain_until_us: timing::micros(expires_at).map_err(|_| invalid())?,
        });
        Ok(())
    }
}
fn invalid() -> SamlError {
    SamlError::Invalid("unsupported or repeated replay reservation".into())
}
