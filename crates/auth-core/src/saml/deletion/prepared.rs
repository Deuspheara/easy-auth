use super::SamlDeletionBinding;
use crate::{SamlPreparedResponse, SamlRegistration};
use std::fmt;

/// Consumed deletion-purpose request, not signature evidence or erasure authority.
/// No public constructor/conversion can turn this into a sign-in preparation.
#[must_use]
pub struct SamlPreparedDeletion {
    pub(super) response: SamlPreparedResponse,
    pub(super) binding: SamlDeletionBinding,
}
impl SamlPreparedDeletion {
    pub fn registration(&self) -> &SamlRegistration {
        self.response.registration()
    }
    pub fn request_id(&self) -> &str {
        self.response.request_id()
    }
    pub fn expires_at_us(&self) -> i64 {
        self.response.expires_at_us()
    }
    pub fn binding(&self) -> &SamlDeletionBinding {
        &self.binding
    }
}
impl fmt::Debug for SamlPreparedDeletion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SamlPreparedDeletion([REDACTED; not authenticated])")
    }
}
