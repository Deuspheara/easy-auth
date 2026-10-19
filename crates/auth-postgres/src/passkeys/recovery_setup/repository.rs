use crate::{Postgres, unavailable};
use async_trait::async_trait;
use auth_core::{
    Error, PasskeyRecoverySetupRepository, PasskeyRecoverySetupRequest, Result, Verifier,
};
use uuid::Uuid;

#[async_trait]
impl PasskeyRecoverySetupRepository for Postgres {
    async fn prepare_passkey_recovery_code(
        &self,
        request: &PasskeyRecoverySetupRequest,
        id: Uuid,
        code: Verifier,
    ) -> Result<()> {
        admit(self, request).await?;
        super::configuration::prepare(&self.pool, request, id, code).await
    }

    async fn confirm_passkey_recovery_code(
        &self,
        request: &PasskeyRecoverySetupRequest,
        id: Uuid,
        code: Verifier,
    ) -> Result<()> {
        admit(self, request).await?;
        super::configuration::confirm(&self.pool, request, id, code).await
    }
}

async fn admit(store: &Postgres, request: &PasskeyRecoverySetupRequest) -> Result<()> {
    // Snapshot chooses only an abuse bucket. The transaction revalidates authority.
    let user: Uuid =
        sqlx::query_scalar("SELECT user_id FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2")
            .bind(request.realm)
            .bind(request.session.as_slice())
            .fetch_optional(&store.pool)
            .await
            .map_err(unavailable)?
            .ok_or(Error::Unauthorized)?;
    store
        .admit_user_action(request.realm, user, request.source)
        .await
}
