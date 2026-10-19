use super::{authorization, notifications};
use crate::{audit, unavailable};
use auth_core::{AuditEvent, Error, PasskeyManagementRequest, Result};
use sqlx::PgPool;
use uuid::Uuid;

pub(super) async fn rename(
    pool: &PgPool,
    request: &PasskeyManagementRequest,
    id: Uuid,
    version: Uuid,
    label: &str,
) -> Result<Uuid> {
    let mut tx = pool.begin().await.map_err(unavailable)?;
    let caller = authorization::caller(&mut tx, request).await?;
    authorization::lock_key(&mut tx, request, caller.user, id, version).await?;
    let next = Uuid::new_v4();
    sqlx::query(
        "UPDATE auth_passkeys SET label=$3,management_version=$4 WHERE realm_id=$1 AND id=$2",
    )
    .bind(request.realm)
    .bind(id)
    .bind(label)
    .bind(next)
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    audit::record(
        &mut tx,
        request.realm,
        AuditEvent::PasskeyRenamed {
            passkey_id: id,
            user_id: caller.user,
            actor_session_id: caller.session,
        },
    )
    .await?;
    notifications::notify(&mut tx, request.realm, caller.user).await?;
    caller.deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)?;
    Ok(next)
}

pub(super) async fn remove(
    pool: &PgPool,
    request: &PasskeyManagementRequest,
    id: Uuid,
    version: Uuid,
) -> Result<()> {
    let mut tx = pool.begin().await.map_err(unavailable)?;
    let caller = authorization::caller(&mut tx, request).await?;
    authorization::lock_key(&mut tx, request, caller.user, id, version).await?;
    // Registration alone cannot establish that the final remaining key works.
    let remaining: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM auth_passkeys WHERE realm_id=$1 AND user_id=$2 AND rp_id=$3 AND id<>$4 AND last_used_at IS NOT NULL)",
    ).bind(request.realm).bind(caller.user).bind(&request.rp_id).bind(id)
        .fetch_one(&mut *tx).await.map_err(unavailable)?;
    if !remaining {
        return Err(Error::Unauthorized);
    }
    sqlx::query(
        "DELETE FROM auth_passkeys WHERE realm_id=$1 AND user_id=$2 AND rp_id=$3 AND id=$4",
    )
    .bind(request.realm)
    .bind(caller.user)
    .bind(&request.rp_id)
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    sqlx::query("UPDATE auth_sessions SET revoked_at=clock_timestamp() WHERE realm_id=$1 AND user_id=$2 AND revoked_at IS NULL")
        .bind(request.realm).bind(caller.user).execute(&mut *tx).await.map_err(unavailable)?;
    for table in [
        "auth_passkey_enrollments",
        "auth_passkey_authentications",
        "auth_email_attachments",
        "auth_email_changes",
        "auth_account_deletions",
    ] {
        // Fixed identifiers only. Discoverable completions must still recheck the key under owner lock.
        sqlx::query(&format!(
            "DELETE FROM {table} WHERE realm_id=$1 AND user_id=$2"
        ))
        .bind(request.realm)
        .bind(caller.user)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
    }
    audit::record(
        &mut tx,
        request.realm,
        AuditEvent::PasskeyRemoved {
            passkey_id: id,
            user_id: caller.user,
            actor_session_id: caller.session,
        },
    )
    .await?;
    notifications::notify(&mut tx, request.realm, caller.user).await?;
    caller.deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)
}
