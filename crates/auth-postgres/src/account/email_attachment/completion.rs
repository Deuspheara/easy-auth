use super::ownership;
use crate::{Postgres, audit, locking::lock_email, unavailable};
use auth_core::{AuditEvent, Error, Result, Verifier};
use uuid::Uuid;

impl Postgres {
    pub(crate) async fn finish_email_attachment(
        &self,
        realm: Uuid,
        current: Verifier,
        token: Verifier,
        browser: Verifier,
        replacement: Verifier,
    ) -> Result<()> {
        let (user, email): (Uuid, String) = sqlx::query_as(
            r#"
            SELECT a.user_id,a.email FROM auth_email_attachments a
            JOIN auth_sessions s ON s.realm_id=a.realm_id AND s.id=a.session_id AND s.user_id=a.user_id
            WHERE a.realm_id=$1 AND a.token_hash=$2 AND a.browser_hash=$3 AND s.token_hash=$4
              AND a.expires_at>clock_timestamp()
            "#,
        ).bind(realm).bind(token.as_slice()).bind(browser.as_slice()).bind(current.as_slice())
            .fetch_optional(&self.pool).await.map_err(unavailable)?.ok_or(Error::Unauthorized)?;
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        lock_email(&mut tx, realm, &email).await?;
        let actor = ownership::lock_fresh(&mut tx, realm, user, current).await?;
        // Separate row lock and clock statement handles unchanged-row waits too.
        sqlx::query_scalar::<_, Uuid>("SELECT user_id FROM auth_email_attachments WHERE realm_id=$1 AND user_id=$2 FOR UPDATE")
            .bind(realm).bind(user).fetch_optional(&mut *tx).await.map_err(unavailable)?
            .ok_or(Error::Unauthorized)?;
        sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT user_id FROM auth_email_attachments WHERE realm_id=$1 AND user_id=$2
              AND session_id=$3 AND token_hash=$4 AND browser_hash=$5 AND email=$6
              AND expires_at>clock_timestamp()
            "#,
        )
        .bind(realm)
        .bind(user)
        .bind(actor)
        .bind(token.as_slice())
        .bind(browser.as_slice())
        .bind(&email)
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Unauthorized)?;
        let occupied: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM auth_users WHERE realm_id=$1 AND email=$2)",
        )
        .bind(realm)
        .bind(&email)
        .fetch_one(&mut *tx)
        .await
        .map_err(unavailable)?;
        if occupied {
            return Err(Error::Unauthorized);
        }
        sqlx::query("UPDATE auth_users SET email=$3,email_verified_at=clock_timestamp() WHERE realm_id=$1 AND id=$2")
            .bind(realm).bind(user).bind(&email).execute(&mut *tx).await.map_err(unavailable)?;
        sqlx::query("UPDATE auth_sessions SET revoked_at=clock_timestamp() WHERE realm_id=$1 AND user_id=$2 AND revoked_at IS NULL")
            .bind(realm).bind(user).execute(&mut *tx).await.map_err(unavailable)?;
        for table in ["auth_email_challenges", "auth_password_resets"] {
            sqlx::query(&format!(
                "DELETE FROM {table} WHERE realm_id=$1 AND email=$2"
            ))
            .bind(realm)
            .bind(&email)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        }
        for table in [
            "auth_email_changes",
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
        let session = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO auth_sessions(realm_id,id,user_id,token_hash,authenticated_at,authentication_method)
            SELECT realm_id,$3,user_id,$4,authenticated_at,authentication_method FROM auth_sessions
            WHERE realm_id=$1 AND id=$2 AND user_id=$5 AND authentication_method='passkey'
            "#,
        ).bind(realm).bind(actor).bind(session).bind(replacement.as_slice()).bind(user)
            .execute(&mut *tx).await.map_err(unavailable)?;
        audit::record(
            &mut tx,
            realm,
            AuditEvent::EmailAttached {
                user_id: user,
                actor_session_id: actor,
                session_id: session,
            },
        )
        .await?;
        // The initial live/fresh session remains locked. Its revocation above is
        // ours; recheck its original method/time and proof expiry AFTER all writes.
        let consumed = sqlx::query(
            r#"
            DELETE FROM auth_email_attachments a USING auth_sessions s
            WHERE a.realm_id=$1 AND a.user_id=$2 AND a.session_id=$3 AND a.token_hash=$4
              AND a.browser_hash=$5 AND a.email=$6 AND a.expires_at>clock_timestamp()
              AND s.realm_id=a.realm_id AND s.id=a.session_id AND s.user_id=a.user_id
              AND s.token_hash=$7 AND s.authentication_method='passkey'
              AND s.authenticated_at>clock_timestamp()-interval '5 minutes'
              AND s.authenticated_at<=clock_timestamp() AND s.expires_at>clock_timestamp()
              AND s.last_seen_at>clock_timestamp()-interval '30 minutes'
            "#,
        )
        .bind(realm)
        .bind(user)
        .bind(actor)
        .bind(token.as_slice())
        .bind(browser.as_slice())
        .bind(&email)
        .bind(current.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        if consumed.rows_affected() != 1 {
            return Err(Error::Unauthorized);
        }
        tx.commit().await.map_err(unavailable)
    }
}
