use super::{admission, mutation};
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
        admission::admit(self, request).await?;
        mutation::rename(&self.pool, request, id, version, label).await
    }

    async fn remove_passkey(
        &self,
        request: &PasskeyManagementRequest,
        id: Uuid,
        version: Uuid,
    ) -> Result<()> {
        admission::admit(self, request).await?;
        mutation::remove(&self.pool, request, id, version).await
    }
}
