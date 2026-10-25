use crate::unavailable;
use auth_core::{Error, OidcMappedIdentity, Result};
use sqlx::{Postgres, Transaction};

const DELETED_SUBJECT_CLEANUP_BATCH: i64 = 32;

pub(super) async fn lock(
    tx: &mut Transaction<'_, Postgres>,
    mapped: &OidcMappedIdentity,
) -> Result<()> {
    let proof = mapped.identity();
    let c = proof.configuration();
    // Canonical scoped hash is a serialization key, not authentication authority.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(encode(auth_oidc_subject_key($1,$2,$3,$4,$5),'hex'),0))")
        .bind(c.realm())
        .bind(c.connection())
        .bind(c.client())
        .bind(c.issuer())
        .bind(proof.subject())
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
    // Only a new-owner path prunes expired hashes, before acquiring any owner lock.
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
