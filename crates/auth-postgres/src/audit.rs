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
    if let (Some(client), Some(authorization)) =
        (event.issuer_client_id(), event.issuer_authorization_id())
    {
        // New issuer facts have their own exact tuple. Existing event inserts
        // retain their original columns; no schema probing or fallback exists.
        sqlx::query(
            r#"
            INSERT INTO auth_audit(realm_id,user_id,kind,schema_version,
                actor_session_id,issuer_client_id,issuer_authorization_id,occurred_at)
            VALUES ($1,$2,$3,1,$4,$5,$6,clock_timestamp())
        "#,
        )
        .bind(realm)
        .bind(event.user_id())
        .bind(event.kind())
        .bind(event.actor_session_id())
        .bind(client)
        .bind(authorization)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    } else {
        sqlx::query(r#"
            INSERT INTO auth_audit(realm_id,user_id,kind,schema_version,actor_session_id,session_id,subject_erased,occurred_at,passkey_id,recovery_claim_id)
            VALUES ($1,$2,$3,1,$4,$5,$6,clock_timestamp(),$7,$8)
        "#)
        .bind(realm).bind(event.user_id()).bind(event.kind())
        .bind(event.actor_session_id()).bind(event.session_id()).bind(event.user_id().is_none())
        .bind(event.passkey_id()).bind(event.recovery_claim_id())
        .execute(&mut **tx).await.map_err(unavailable)?;
    }
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
        UPDATE auth_audit SET user_id=NULL,actor_session_id=NULL,session_id=NULL,passkey_id=NULL,recovery_claim_id=NULL,issuer_client_id=NULL,issuer_authorization_id=NULL,subject_erased=true
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
