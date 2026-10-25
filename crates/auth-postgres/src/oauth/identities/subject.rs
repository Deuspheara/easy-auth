use crate::unavailable;
use auth_core::{Error, OidcMappedIdentity, Result};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

const DELETED_SUBJECT_CLEANUP_BATCH: i64 = 32;

pub(super) async fn lock(
    tx: &mut Transaction<'_, Postgres>,
    realm: Uuid,
    connection: Uuid,
    client: Uuid,
    issuer: &str,
    subject: &str,
) -> Result<()> {
    // Canonical scoped hash is a serialization key, not authentication authority.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(encode(auth_oidc_subject_key($1,$2,$3,$4,$5),'hex'),0))")
        .bind(realm)
        .bind(connection)
        .bind(client)
        .bind(issuer)
        .bind(subject)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    Ok(())
}

pub(super) async fn reject_deleted(
    tx: &mut Transaction<'_, Postgres>,
    mapped: &OidcMappedIdentity,
) -> Result<()> {
    let c = mapped.identity().configuration();
    // Call before acquiring any owner lock. Neither JIT nor an explicit link can
    // reuse a subject while an original pre-removal proof may still be live.
    sqlx::query(
        r#"
        DELETE FROM auth_oidc_deleted_subjects WHERE ctid IN (
          SELECT ctid FROM auth_oidc_deleted_subjects
          WHERE realm_id=$1 AND blocked_until<=clock_timestamp()
          ORDER BY blocked_until LIMIT $2 FOR UPDATE SKIP LOCKED)
    "#,
    )
    .bind(c.realm())
    .bind(DELETED_SUBJECT_CLEANUP_BATCH)
    .execute(&mut **tx)
    .await
    .map_err(unavailable)?;
    let blocked: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(SELECT 1 FROM auth_oidc_deleted_subjects
        WHERE realm_id=$1 AND subject_hash=auth_oidc_subject_key($1,$2,$3,$4,$5)
          AND blocked_until>clock_timestamp())
    "#,
    )
    .bind(c.realm())
    .bind(c.connection())
    .bind(c.client())
    .bind(c.issuer())
    .bind(mapped.identity().subject())
    .fetch_one(&mut **tx)
    .await
    .map_err(unavailable)?;
    if blocked {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

#[cfg(feature = "oidc-linking")]
pub(super) async fn remember_deleted(
    tx: &mut Transaction<'_, Postgres>,
    realm: Uuid,
    connection: Uuid,
    client: Uuid,
    issuer: &str,
    subject: &str,
) -> Result<()> {
    sqlx::query("INSERT INTO auth_oidc_deleted_subjects(realm_id,subject_hash,blocked_until) VALUES($1,auth_oidc_subject_key($1,$2,$3,$4,$5),clock_timestamp()+interval '5 minutes') ON CONFLICT(realm_id,subject_hash) DO UPDATE SET blocked_until=greatest(auth_oidc_deleted_subjects.blocked_until,EXCLUDED.blocked_until)")
        .bind(realm).bind(connection).bind(client).bind(issuer).bind(subject).execute(&mut **tx).await.map_err(unavailable)?;
    Ok(())
}
