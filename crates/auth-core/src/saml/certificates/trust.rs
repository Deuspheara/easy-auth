use super::SamlPinnedCertificate;
use crate::{Error, Result};

/// One current certificate and one explicitly approved rotation overlap.
pub const MAX_SAML_PINNED_CERTIFICATES: usize = 2;

/// Fixed operator-approved leaf pins, scoped by the owning registration revision.
/// Construction creates no authority to accept a response or issue a session.
#[derive(Clone, Debug)]
pub struct SamlCertificateTrust {
    certificates: Vec<SamlPinnedCertificate>,
}

impl SamlCertificateTrust {
    pub fn pinned_leaf(certificates: Vec<SamlPinnedCertificate>) -> Result<Self> {
        if certificates.is_empty() || certificates.len() > MAX_SAML_PINNED_CERTIFICATES {
            return Err(Error::InvalidInput);
        }
        if certificates.len() == 2 && certificates[0].fingerprint() == certificates[1].fingerprint()
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self { certificates })
    }

    pub fn certificates(&self) -> &[SamlPinnedCertificate] {
        &self.certificates
    }

    /// No active pin is an authentication failure, never a system-root fallback.
    pub fn active_at(&self, unix_seconds: i64) -> Result<Vec<&SamlPinnedCertificate>> {
        let active: Vec<_> = self
            .certificates
            .iter()
            .filter(|c| c.is_active_at(unix_seconds))
            .collect();
        if active.is_empty() {
            return Err(Error::Unauthorized);
        }
        Ok(active)
    }
}
