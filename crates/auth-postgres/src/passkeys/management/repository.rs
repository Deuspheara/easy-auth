use super::super::sensitive_admission::admit_sensitive_action;
use super::mutation;
use crate::Postgres;
use async_trait::async_trait;
use auth_core::{PasskeyInfo, PasskeyManagementRepository, PasskeyManagementRequest, Result};
use uuid::Uuid;

#[async_trait]
impl PasskeyManagementRepository for Postgres {
    async fn list_passkeys(&self, request: &PasskeyManagementRequest) -> Result<Vec<PasskeyInfo>> {
        super::inventory::list(&self.pool, request).await
    }

    async fn rename_passkey(
        &self,
        request: &PasskeyManagementRequest,
        id: Uuid,
        version: Uuid,
        label: &str,
    ) -> Result<Uuid> {
        admit_sensitive_action(self, request.realm, request.session, request.source).await?;
        mutation::rename(&self.pool, request, id, version, label).await
    }

    async fn remove_passkey(
        &self,
        request: &PasskeyManagementRequest,
        id: Uuid,
        version: Uuid,
    ) -> Result<()> {
        admit_sensitive_action(self, request.realm, request.session, request.source).await?;
        mutation::remove(&self.pool, request, id, version).await
    }
}
