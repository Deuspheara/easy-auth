use crate::audit;
use crate::locking::{fresh_account, lock_email};
use crate::{Postgres, unavailable};
use auth_core::AuditEvent;
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
        let revoked: Option<Uuid> = sqlx::query_scalar(
            r#"
            UPDATE auth_sessions SET revoked_at=clock_timestamp()
            WHERE realm_id=$1 AND user_id=$2 AND id=$3 AND revoked_at IS NULL
              AND expires_at>clock_timestamp()
              AND last_seen_at>clock_timestamp()-interval '30 minutes'
            RETURNING id
        "#,
        )
        .bind(realm)
        .bind(user)
        .bind(target)
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?;
        if let Some(session_id) = revoked {
            audit::record(
                &mut tx,
                realm,
                AuditEvent::SessionRevoked {
                    user_id: user,
                    actor_session_id: caller,
                    session_id,
                },
            )
            .await?;
        }
        tx.commit().await.map_err(unavailable)?;
        Ok(revoked == Some(caller))
    }

    pub(crate) async fn revoke_all_sessions(&self, realm: Uuid, current: Verifier) -> Result<()> {
        let email = self.current_email(realm, current).await?;
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        // Issuers and lifecycle mutations use this same email -> user -> session ordering.
        lock_email(&mut tx, realm, &email).await?;
        let (user, actor_session_id) = fresh_account(&mut tx, realm, current, &email).await?;
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
        audit::record(
            &mut tx,
            realm,
            AuditEvent::AllSessionsRevoked {
                user_id: user,
                actor_session_id,
            },
        )
        .await?;
        tx.commit().await.map_err(unavailable)
    }
}
