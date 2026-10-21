use crate::{Result, SamlCertificateTrust, SamlRegistration};
use async_trait::async_trait;

/// Trusted configuration and a fresh database clock, never signature evidence.
pub struct SamlVerificationMaterial {
    pub trust: SamlCertificateTrust,
    pub observed_at_us: i64,
}

#[async_trait]
pub trait SamlVerificationRepository: Send + Sync {
    /// Require the exact current enabled realm/connection/client/revision. Release
    /// storage locks before certificate parsing and cryptographic verification.
    /// Final authority must check that revision and every deadline again.
    async fn load_saml_verification_material(
        &self,
        registration: &SamlRegistration,
    ) -> Result<SamlVerificationMaterial>;
}
