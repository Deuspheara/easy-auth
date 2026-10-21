use crate::{Postgres, unavailable};
use async_trait::async_trait;
use auth_core::{Result, SamlRegistration, SamlVerificationMaterial, SamlVerificationRepository};

#[async_trait]
impl SamlVerificationRepository for Postgres {
    async fn load_saml_verification_material(
        &self,
        registration: &SamlRegistration,
    ) -> Result<SamlVerificationMaterial> {
        let trust = self.saml_certificate_trust(registration).await?;
        // Current enabled revision was locked for the pin snapshot; locks have
        // already been released. This fresh clock avoids using preparation time
        // after a configuration/pool wait. Final authority must recheck revision.
        let observed_at_us: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000000)::bigint",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(unavailable)?;
        Ok(SamlVerificationMaterial {
            trust,
            observed_at_us,
        })
    }
}
