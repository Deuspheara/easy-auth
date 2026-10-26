use crate::{Postgres, unavailable};
use auth_core::{Error, Result};
use uuid::Uuid;
impl Postgres {
    /// Trusted realm maintenance. Bounded batches erase expired ciphertext and
    /// eventually terminal metadata, never represent expiry as confirmed revocation.
    /// This requires scheduled invocation; a timestamp alone is not a database TTL.
    pub async fn maintain_apple_grants(&self, realm: Uuid) -> Result<u64> {
        if realm.is_nil() {
            return Err(Error::InvalidInput);
        }
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let expired = sqlx::query(
            r#"
            WITH due AS (
                SELECT id FROM auth_apple_grants
                WHERE realm_id=$1 AND state IN ('pending','leased','failed')
                  AND expires_at<=clock_timestamp()
                ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 64
            )
            UPDATE auth_apple_grants g
            SET state='expired',ciphertext=NULL,key_id=NULL,lease_id=NULL,lease_until=NULL,
                finished_at=clock_timestamp(),failure='expired',version=version+1
            FROM due WHERE g.realm_id=$1 AND g.id=due.id
            "#,
        )
        .bind(realm)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?
        .rows_affected();
        sqlx::query(
            r#"
            WITH due AS (
                SELECT id FROM auth_apple_grants
                WHERE realm_id=$1 AND state='leased' AND attempts=8
                  AND lease_until<=clock_timestamp() AND expires_at>clock_timestamp()
                ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 64
            )
            UPDATE auth_apple_grants g
            SET state='failed',lease_id=NULL,lease_until=NULL,
                failure='unavailable',version=version+1
            FROM due WHERE g.realm_id=$1 AND g.id=due.id
            "#,
        )
        .bind(realm)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        sqlx::query(
            r#"
            WITH due AS (
                SELECT id FROM auth_apple_grants
                WHERE realm_id=$1 AND state IN ('completed','expired')
                  AND finished_at<=clock_timestamp()-interval '604800 seconds'
                ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 64
            )
            DELETE FROM auth_apple_grants g USING due
            WHERE g.realm_id=$1 AND g.id=due.id
            "#,
        )
        .bind(realm)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(expired)
    }
}
