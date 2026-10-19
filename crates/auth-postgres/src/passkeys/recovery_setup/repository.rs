use super::super::sensitive_admission::admit_sensitive_action;
use crate::Postgres;
use async_trait::async_trait;
use auth_core::{PasskeyRecoverySetupRepository, PasskeyRecoverySetupRequest, Result, Verifier};
use uuid::Uuid;

#[async_trait]
impl PasskeyRecoverySetupRepository for Postgres {
    async fn prepare_passkey_recovery_code(
        &self,
        request: &PasskeyRecoverySetupRequest,
        id: Uuid,
        code: Verifier,
    ) -> Result<()> {
        admit_sensitive_action(self, request.realm, request.session, request.source).await?;
        super::configuration::prepare(&self.pool, request, id, code).await
    }

    async fn confirm_passkey_recovery_code(
        &self,
        request: &PasskeyRecoverySetupRequest,
        id: Uuid,
        code: Verifier,
    ) -> Result<()> {
        admit_sensitive_action(self, request.realm, request.session, request.source).await?;
        super::configuration::confirm(&self.pool, request, id, code).await
    }
}
