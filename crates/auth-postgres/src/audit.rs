use crate::unavailable;
use auth_core::{AuditEvent, Result};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Called under the owning user's lock, in the same transaction as the verified mutation.
/// Composite foreign keys check subject/actor/target ownership, including the configured realm.
pub(crate) async fn record(
    tx: &mut Transaction<'_, Postgres>,
    realm: Uuid,
    event: AuditEvent,
) -> Result<()> {
    sqlx::query(r#"
        INSERT INTO auth_audit(realm_id,user_id,kind,schema_version,actor_session_id,session_id,subject_erased,occurred_at)
        VALUES ($1,$2,$3,1,$4,$5,$6,clock_timestamp())
    "#)
        .bind(realm).bind(event.user_id()).bind(event.kind())
        .bind(event.actor_session_id()).bind(event.session_id()).bind(event.user_id().is_none())
        .execute(&mut **tx).await.map_err(unavailable)?;
    Ok(())
}

/// Deidentify every reference before deleting the user and its sessions; preserve other subjects.
pub(crate) async fn erase_subject(
    tx: &mut Transaction<'_, Postgres>,
    realm: Uuid,
    user: Uuid,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE auth_audit SET user_id=NULL,actor_session_id=NULL,session_id=NULL,subject_erased=true
        WHERE realm_id=$1 AND user_id=$2
    "#,
    )
    .bind(realm)
    .bind(user)
    .execute(&mut **tx)
    .await
    .map_err(unavailable)?;
    Ok(())
}
