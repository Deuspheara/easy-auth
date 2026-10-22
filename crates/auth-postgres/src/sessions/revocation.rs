use super::ownership::Owner;
use crate::{Postgres, unavailable};
use crate::{audit, deadlines::Deadline};
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
        let owner = Owner::load(&self.pool, realm, current).await?;
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let caller = owner.lock_fresh(&mut tx, realm, current).await?;
        let user = owner.user;
        let deadline = Deadline::fresh_session(&mut tx, realm, user, caller).await?;
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
        #[cfg(feature = "saml-identities")]
        crate::account::cancel_saml_deletion_session_requests(&mut tx, realm, user, target).await?;
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
        deadline.check(&mut tx).await?;
        tx.commit().await.map_err(unavailable)?;
        Ok(revoked == Some(caller))
    }

    pub(crate) async fn revoke_all_sessions(&self, realm: Uuid, current: Verifier) -> Result<()> {
        let owner = Owner::load(&self.pool, realm, current).await?;
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let actor_session_id = owner.lock_fresh(&mut tx, realm, current).await?;
        let user = owner.user;
        let deadline = Deadline::fresh_session(&mut tx, realm, user, actor_session_id).await?;
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
        #[cfg(feature = "saml-identities")]
        crate::account::cancel_saml_deletion_owner_requests(&mut tx, realm, user).await?;
        for table in ["auth_email_challenges", "auth_password_resets"] {
            // Fixed internal identifiers; no client input enters a table name.
            sqlx::query(&format!(
                "DELETE FROM {table} WHERE realm_id=$1 AND email=$2"
            ))
            .bind(realm)
            .bind(&owner.email)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        }
        for table in [
            "auth_email_changes",
            "auth_email_attachments",
            "auth_account_deletions",
            "auth_passkey_enrollments",
            "auth_passkey_authentications",
        ] {
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
        deadline.check(&mut tx).await?;
        tx.commit().await.map_err(unavailable)
    }
}
