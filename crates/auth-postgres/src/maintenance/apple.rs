use crate::unavailable;
use auth_core::{RETENTION_BATCH_LIMIT, Result, RetentionBatch};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[cfg(feature = "apple-grants")]
impl crate::Postgres {
    /// Trusted realm maintenance. Bounded batches erase expired ciphertext and
    /// eventually terminal metadata, never represent expiry as confirmed revocation.
    /// This requires scheduled invocation; a timestamp alone is not a database TTL.
    pub async fn maintain_apple_grants(&self, realm: Uuid) -> Result<u64> {
        use auth_core::{
            RetentionCategory, RetentionHorizon, RetentionPolicy, RetentionRepository,
        };
        let effects = self
            .retain_batch(
                realm,
                RetentionCategory::AppleGrants,
                RetentionPolicy::new(RetentionHorizon::keep(), RetentionHorizon::keep()),
            )
            .await?;
        Ok(effects.expired_ciphertexts)
    }
}

pub(super) async fn retain(
    tx: &mut Transaction<'_, Postgres>,
    realm: Uuid,
) -> Result<RetentionBatch> {
    let expired = sqlx::query(
        r#"
            WITH due AS (
                SELECT id FROM auth_apple_grants
                WHERE realm_id=$1 AND state IN ('pending','leased','failed')
                  AND expires_at<=statement_timestamp()
                ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $2
            )
            UPDATE auth_apple_grants g
            SET state='expired',ciphertext=NULL,key_id=NULL,lease_id=NULL,lease_until=NULL,
                finished_at=clock_timestamp(),failure='expired',version=version+1
            FROM due WHERE g.realm_id=$1 AND g.id=due.id
            "#,
    )
    .bind(realm)
    .bind(RETENTION_BATCH_LIMIT as i64)
    .execute(&mut **tx)
    .await
    .map_err(unavailable)?
    .rows_affected();
    let exhausted_leases = sqlx::query(
        r#"
            WITH due AS (
                SELECT id FROM auth_apple_grants
                WHERE realm_id=$1 AND state='leased' AND attempts=8
                  AND lease_until<=statement_timestamp() AND expires_at>statement_timestamp()
                ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $2
            )
            UPDATE auth_apple_grants g
            SET state='failed',lease_id=NULL,lease_until=NULL,
                failure='unavailable',version=version+1
            FROM due WHERE g.realm_id=$1 AND g.id=due.id
            "#,
    )
    .bind(realm)
    .bind(RETENTION_BATCH_LIMIT as i64)
    .execute(&mut **tx)
    .await
    .map_err(unavailable)?
    .rows_affected();
    let deleted = sqlx::query(
        r#"
            WITH due AS (
                SELECT id FROM auth_apple_grants
                WHERE realm_id=$1 AND state IN ('completed','expired')
                  AND finished_at<=statement_timestamp()-interval '604800 seconds'
                ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $2
            )
            DELETE FROM auth_apple_grants g USING due
            WHERE g.realm_id=$1 AND g.id=due.id
            "#,
    )
    .bind(realm)
    .bind(RETENTION_BATCH_LIMIT as i64)
    .execute(&mut **tx)
    .await
    .map_err(unavailable)?
    .rows_affected();
    Ok(RetentionBatch {
        deleted,
        expired_ciphertexts: expired,
        exhausted_leases,
    })
}
