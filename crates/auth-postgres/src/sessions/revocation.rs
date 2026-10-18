use crate::locking::{fresh_account, lock_email};
use crate::{Postgres, unavailable};
use auth_core::{Result, Verifier};
use uuid::Uuid;

impl Postgres {
    pub(crate) async fn revoke_session(
        &self,
        realm: Uuid,
        current: Verifier,
        target: Uuid,
    ) -> Result<bool> {
        let email = self.current_email(realm, current).await?;
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let (user, caller) = fresh_account(&mut tx, realm, current, &email).await?;
        let revoked = sqlx::query(
            r#"
            WITH revoked AS (
                UPDATE auth_sessions SET revoked_at=clock_timestamp()
                WHERE realm_id=$1 AND user_id=$2 AND id=$3 AND revoked_at IS NULL
                  AND expires_at>clock_timestamp()
                  AND last_seen_at>clock_timestamp()-interval '30 minutes'
                RETURNING user_id
            )
            INSERT INTO auth_audit(realm_id,user_id,kind)
                SELECT $1,user_id,'session_revoked' FROM revoked
            "#,
        )
        .bind(realm)
        .bind(user)
        .bind(target)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(target == caller && revoked.rows_affected() == 1)
    }

    pub(crate) async fn revoke_all_sessions(&self, realm: Uuid, current: Verifier) -> Result<()> {
        let email = self.current_email(realm, current).await?;
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        // Issuers and lifecycle mutations use this same email -> user -> session ordering.
        lock_email(&mut tx, realm, &email).await?;
        let (user, _) = fresh_account(&mut tx, realm, current, &email).await?;
        sqlx::query(
            r#"
            UPDATE auth_sessions SET revoked_at=clock_timestamp()
            WHERE realm_id=$1 AND user_id=$2 AND revoked_at IS NULL
            "#,
        )
        .bind(realm)
        .bind(user)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        for table in ["auth_email_challenges", "auth_password_resets"] {
            // Fixed internal identifiers; no client input enters a table name.
            sqlx::query(&format!(
                "DELETE FROM {table} WHERE realm_id=$1 AND email=$2"
            ))
            .bind(realm)
            .bind(&email)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        }
        for table in ["auth_email_changes", "auth_account_deletions"] {
            sqlx::query(&format!(
                "DELETE FROM {table} WHERE realm_id=$1 AND user_id=$2"
            ))
            .bind(realm)
            .bind(user)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        }
        sqlx::query(
            "INSERT INTO auth_audit(realm_id,user_id,kind) VALUES ($1,$2,'all_sessions_revoked')",
        )
        .bind(realm)
        .bind(user)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)
    }
}
