use crate::Postgres;
use async_trait::async_trait;
use auth_core::{
    Result, SamlDeletionRequestContext, SamlDeletionRequestRepository, SamlRegistration,
    SamlRequestAdmission, Verifier,
};

#[async_trait]
impl SamlDeletionRequestRepository for Postgres {
    async fn save_saml_deletion_request(
        &self,
        reg: &SamlRegistration,
        current: Verifier,
        admission: SamlRequestAdmission<'_>,
    ) -> Result<i64> {
        super::preparation::save(self, reg, current, admission).await
    }
    async fn cancel_saml_deletion_request(
        &self,
        reg: &SamlRegistration,
        current: Verifier,
        admission: SamlRequestAdmission<'_>,
    ) -> Result<()> {
        super::consumption::take(self, reg, current, admission).await?;
        Ok(())
    }
    async fn take_saml_deletion_request(
        &self,
        reg: &SamlRegistration,
        current: Verifier,
        admission: SamlRequestAdmission<'_>,
    ) -> Result<SamlDeletionRequestContext> {
        super::consumption::take(self, reg, current, admission).await
    }
}
