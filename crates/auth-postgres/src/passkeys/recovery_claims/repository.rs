use super::{admission, beginning, cancellation, ownership};
use crate::{Postgres, unavailable};
use async_trait::async_trait;
use auth_core::{
    PasskeyRecoveryClaimInfo, PasskeyRecoveryClaimRepository, PasskeyRecoveryClaimRequest,
    PasskeyRecoveryKeyCancellation, Result, Verifier,
};
use uuid::Uuid;

#[async_trait]
impl PasskeyRecoveryClaimRepository for Postgres {
    async fn cancel_passkey_recovery_with_code(
        &self,
        request: &auth_core::PasskeyRecoveryCodeCancellation,
    ) -> Result<()> {
        admission::admit_source(self, request.realm, request.source).await?;
        cancellation::code(&self.pool, request).await
    }
    async fn begin_passkey_recovery_claim(
        &self,
        request: &PasskeyRecoveryClaimRequest,
        id: Uuid,
        code: Verifier,
    ) -> Result<PasskeyRecoveryClaimInfo> {
        admission::admit(self, request, admission::Budget::Code).await?;
        beginning::begin(&self.pool, request, id, code).await
    }

    async fn resume_passkey_recovery_claim(
        &self,
        request: &PasskeyRecoveryClaimRequest,
    ) -> Result<PasskeyRecoveryClaimInfo> {
        metadata(self, request, None).await
    }

    async fn passkey_recovery_claim(
        &self,
        request: &PasskeyRecoveryClaimRequest,
        id: Uuid,
    ) -> Result<PasskeyRecoveryClaimInfo> {
        metadata(self, request, Some(id)).await
    }

    async fn cancel_passkey_recovery_claim(
        &self,
        request: &PasskeyRecoveryClaimRequest,
        id: Uuid,
    ) -> Result<()> {
        admission::admit(self, request, admission::Budget::Browser).await?;
        cancellation::browser(&self.pool, request, id).await
    }

    async fn cancel_passkey_recovery_with_key(
        &self,
        request: &PasskeyRecoveryKeyCancellation,
        id: Uuid,
    ) -> Result<()> {
        super::super::sensitive_admission::admit_sensitive_action(
            self,
            request.realm,
            request.session,
            request.source,
        )
        .await?;
        cancellation::key(&self.pool, request, id).await
    }
}

async fn metadata(
    store: &Postgres,
    request: &PasskeyRecoveryClaimRequest,
    id: Option<Uuid>,
) -> Result<PasskeyRecoveryClaimInfo> {
    admission::admit(store, request, admission::Budget::Browser).await?;
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    ownership::owner(&mut tx, request.realm, request.user_id).await?;
    let id = match id {
        Some(id) => id,
        None => sqlx::query_scalar("SELECT id FROM auth_passkey_recovery_claims WHERE realm_id=$1 AND user_id=$2 AND rp_id=$3 AND browser_hash=$4")
            .bind(request.realm).bind(request.user_id).bind(&request.rp_id).bind(request.browser.as_slice())
            .fetch_optional(&mut *tx).await.map_err(unavailable)?.ok_or(auth_core::Error::Unauthorized)?,
    };
    let deadline = ownership::claim(
        &mut tx,
        request.realm,
        request.user_id,
        &request.rp_id,
        id,
        Some(request.browser),
    )
    .await?;
    let info = ownership::info(&mut tx, request.realm, request.user_id, &request.rp_id, id).await?;
    deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)?;
    Ok(info)
}
