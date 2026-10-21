use crate::unavailable;
use auth_core::{Error, Result, SamlMappedIdentity};
use sqlx::{Postgres, Transaction};

const CLEANUP_BATCH: i64 = 32;

pub(super) async fn reject(
    tx: &mut Transaction<'_, Postgres>,
    mapped: &SamlMappedIdentity,
) -> Result<()> {
    let reg = mapped.assertion().registration();
    // New-owner path only, before acquiring an owner lock. Deletion itself never
    // takes source/advisory locks, preserving owner-deletion lock ordering.
    sqlx::query("DELETE FROM auth_saml_deleted_subjects WHERE ctid IN (SELECT ctid FROM auth_saml_deleted_subjects WHERE realm_id=$1 AND blocked_until<=clock_timestamp() ORDER BY blocked_until LIMIT $2 FOR UPDATE SKIP LOCKED)")
        .bind(reg.realm()).bind(CLEANUP_BATCH).execute(&mut **tx).await.map_err(unavailable)?;
    let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auth_saml_deleted_subjects WHERE realm_id=$1 AND subject_hash=auth_saml_subject_key($1,$2,$3,$4,$5,$6) AND blocked_until>clock_timestamp())")
        .bind(reg.realm()).bind(reg.connection()).bind(reg.client()).bind(reg.idp_entity()).bind(reg.sp_entity()).bind(mapped.assertion().subject())
        .fetch_one(&mut **tx).await.map_err(unavailable)?;
    if blocked {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
