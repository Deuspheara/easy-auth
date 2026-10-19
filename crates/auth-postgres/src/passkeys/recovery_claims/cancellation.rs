use super::ownership;
use crate::{audit, unavailable};
use auth_core::{AuditEvent, PasskeyRecoveryClaimRequest, PasskeyRecoveryKeyCancellation, Result};
use sqlx::{PgPool, Transaction};
use uuid::Uuid;

pub(super) async fn code(
    pool: &PgPool,
    request: &auth_core::PasskeyRecoveryCodeCancellation,
) -> Result<()> {
    let mut tx = pool.begin().await.map_err(unavailable)?;
    ownership::owner(&mut tx, request.realm, request.user_id).await?;
    let id:Uuid=sqlx::query_scalar(r#"
        SELECT c.id FROM auth_passkey_recovery_codes k
        JOIN auth_passkey_recovery_claims c ON c.realm_id=k.realm_id AND c.user_id=k.user_id AND c.rp_id=k.rp_id
        WHERE k.realm_id=$1 AND k.user_id=$2 AND k.rp_id=$3 AND k.code_hash=$4
          AND k.consumed_at IS NOT NULL AND c.code_version=k.version FOR UPDATE OF k
    "#).bind(request.realm).bind(request.user_id).bind(&request.rp_id).bind(request.code.as_slice())
        .fetch_optional(&mut *tx).await.map_err(unavailable)?.ok_or(auth_core::Error::Unauthorized)?;
    let deadline = ownership::claim(
        &mut tx,
        request.realm,
        request.user_id,
        &request.rp_id,
        id,
        None,
    )
    .await?;
    cancel(&mut tx, request.realm, request.user_id, id, None).await?;
    deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)
}

pub(super) async fn browser(
    pool: &PgPool,
    request: &PasskeyRecoveryClaimRequest,
    id: Uuid,
) -> Result<()> {
    let mut tx = pool.begin().await.map_err(unavailable)?;
    ownership::owner(&mut tx, request.realm, request.user_id).await?;
    let deadline = ownership::claim(
        &mut tx,
        request.realm,
        request.user_id,
        &request.rp_id,
        id,
        Some(request.browser),
    )
    .await?;
    cancel(&mut tx, request.realm, request.user_id, id, None).await?;
    deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)
}

pub(super) async fn key(
    pool: &PgPool,
    request: &PasskeyRecoveryKeyCancellation,
    id: Option<Uuid>,
) -> Result<()> {
    let mut tx = pool.begin().await.map_err(unavailable)?;
    let caller =
        super::super::authority::fresh_passkey_caller(&mut tx, request.realm, request.session)
            .await?;
    let id=match id {
        Some(id)=>id,
        None=>sqlx::query_scalar("SELECT id FROM auth_passkey_recovery_claims WHERE realm_id=$1 AND user_id=$2 AND rp_id=$3 AND cancelled_at IS NULL AND completed_at IS NULL")
            .bind(request.realm).bind(caller.user).bind(&request.rp_id).fetch_optional(&mut *tx).await.map_err(unavailable)?.ok_or(auth_core::Error::Unauthorized)?,
    };
    let deadline = ownership::claim(
        &mut tx,
        request.realm,
        caller.user,
        &request.rp_id,
        id,
        None,
    )
    .await?;
    cancel(
        &mut tx,
        request.realm,
        caller.user,
        id,
        Some(caller.session),
    )
    .await?;
    deadline.check(&mut tx).await?;
    caller.deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)
}

async fn cancel(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    realm: Uuid,
    user: Uuid,
    id: Uuid,
    actor_session_id: Option<Uuid>,
) -> Result<()> {
    sqlx::query("UPDATE auth_passkey_recovery_claims SET cancelled_at=clock_timestamp() WHERE realm_id=$1 AND user_id=$2 AND id=$3")
        .bind(realm).bind(user).bind(id).execute(&mut **tx).await.map_err(unavailable)?;
    sqlx::query("DELETE FROM auth_security_notifications WHERE realm_id=$1 AND user_id=$2 AND recovery_claim_id=$3")
        .bind(realm).bind(user).bind(id).execute(&mut **tx).await.map_err(unavailable)?;
    sqlx::query("DELETE FROM auth_passkey_recovery_replacements WHERE realm_id=$1 AND claim_id=$2")
        .bind(realm)
        .bind(id)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    audit::record(
        tx,
        realm,
        AuditEvent::PasskeyRecoveryCancelled {
            user_id: user,
            claim_id: id,
            actor_session_id,
        },
    )
    .await?;
    sqlx::query(
        r#"
        INSERT INTO auth_security_notifications(realm_id,id,user_id,recipient,kind)
        SELECT realm_id,$3,id,email,'passkey_recovery_cancelled' FROM auth_users
        WHERE realm_id=$1 AND id=$2 AND email IS NOT NULL AND email_verified_at IS NOT NULL
    "#,
    )
    .bind(realm)
    .bind(user)
    .bind(Uuid::new_v4())
    .execute(&mut **tx)
    .await
    .map_err(unavailable)?;
    Ok(())
}
