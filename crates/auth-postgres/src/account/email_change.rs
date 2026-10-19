use crate::audit;
use crate::locking::{fresh_account, lock_emails};
use crate::{Postgres, unavailable};
use auth_core::AuditEvent;
use auth_core::{Error, Result, Verifier};
use sqlx::Row;
use uuid::Uuid;

impl Postgres {
    pub(crate) async fn begin_email_change(
        &self,
        realm: Uuid,
        current: Verifier,
        email: &str,
        old: Verifier,
        new: Verifier,
        browser: Verifier,
    ) -> Result<String> {
        let previous = self.current_email(realm, current).await?;
        if previous == email {
            return Err(Error::InvalidInput);
        }
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        lock_emails(&mut tx, realm, &previous, email).await?;
        let (user, session) = fresh_account(&mut tx, realm, current, &previous).await?;
        sqlx::query(r#"
    INSERT INTO auth_email_changes(realm_id,id,user_id,session_id,old_email,new_email,old_hash,new_hash,browser_hash)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
"#)
            .bind(realm)
            .bind(Uuid::new_v4())
            .bind(user)
            .bind(session)
            .bind(&previous)
            .bind(email)
            .bind(old.as_slice())
            .bind(new.as_slice())
            .bind(browser.as_slice())
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(previous)
    }
    pub(crate) async fn confirm_email_change(
        &self,
        realm: Uuid,
        current: Verifier,
        token: Verifier,
        browser: Verifier,
    ) -> Result<bool> {
        let pending = sqlx::query(
            r#"
            SELECT old_email,new_email
            FROM auth_email_changes
            WHERE realm_id=$1
            AND browser_hash=$2
            AND (old_hash=$3
            OR new_hash=$3)
            "#,
        )
        .bind(realm)
        .bind(browser.as_slice())
        .bind(token.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Unauthorized)?;
        let old: String = pending.get("old_email");
        let new: String = pending.get("new_email");
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        lock_emails(&mut tx, realm, &old, &new).await?;
        let (user, session) = fresh_account(&mut tx, realm, current, &old).await?;
        let proof = sqlx::query(
            r#"
            SELECT id,old_hash=$5 AS is_old,old_confirmed,new_confirmed
            FROM auth_email_changes
            WHERE realm_id=$1
            AND user_id=$2
            AND session_id=$3
            AND browser_hash=$4
            AND (old_hash=$5
            OR new_hash=$5)
            AND expires_at>clock_timestamp()
            FOR
            UPDATE
            "#,
        )
        .bind(realm)
        .bind(user)
        .bind(session)
        .bind(browser.as_slice())
        .bind(token.as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Unauthorized)?;
        let is_old: bool = proof.get("is_old");
        let old_done: bool = proof.get("old_confirmed");
        let new_done: bool = proof.get("new_confirmed");
        if (is_old && old_done) || (!is_old && new_done) {
            return Err(Error::Unauthorized);
        }
        let complete = if is_old { new_done } else { old_done };
        if complete {
            let occupied: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM auth_users WHERE realm_id=$1 AND email=$2 AND id<>$3)",
            )
            .bind(realm)
            .bind(&new)
            .bind(user)
            .fetch_one(&mut *tx)
            .await
            .map_err(unavailable)?;
            if occupied {
                return Err(Error::Unauthorized);
            }
        }
        sqlx::query(
            r#"
            UPDATE auth_email_changes
            SET old_confirmed=old_confirmed
            OR $3,new_confirmed=new_confirmed
            OR NOT $3
            WHERE realm_id=$1
            AND id=$2
            "#,
        )
        .bind(realm)
        .bind(proof.get::<Uuid, _>("id"))
        .bind(is_old)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        if !complete {
            tx.commit().await.map_err(unavailable)?;
            return Ok(false);
        }
        sqlx::query("UPDATE auth_users SET email=$3,email_verified_at=clock_timestamp() WHERE realm_id=$1 AND id=$2")
            .bind(realm)
            .bind(user)
            .bind(&new)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        sqlx::query(
            "UPDATE auth_password_credentials SET version=$3 WHERE realm_id=$1 AND user_id=$2",
        )
        .bind(realm)
        .bind(user)
        .bind(Uuid::new_v4())
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        sqlx::query("UPDATE auth_sessions SET revoked_at=clock_timestamp() WHERE realm_id=$1 AND user_id=$2 AND revoked_at IS NULL")
            .bind(realm)
            .bind(user)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        for table in ["auth_email_challenges", "auth_password_resets"] {
            // Identifiers are a fixed internal allowlist, never request data.
            sqlx::query(&format!(
                "DELETE FROM {table} WHERE realm_id=$1 AND email IN ($2,$3)"
            ))
            .bind(realm)
            .bind(&old)
            .bind(&new)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        }
        sqlx::query("DELETE FROM auth_email_changes WHERE realm_id=$1 AND user_id=$2")
            .bind(realm)
            .bind(user)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        sqlx::query("DELETE FROM auth_account_deletions WHERE realm_id=$1 AND user_id=$2")
            .bind(realm)
            .bind(user)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        audit::record(
            &mut tx,
            realm,
            AuditEvent::EmailChanged {
                user_id: user,
                actor_session_id: session,
            },
        )
        .await?;
        sqlx::query("DELETE FROM auth_email_attachments WHERE realm_id=$1 AND user_id=$2")
            .bind(realm)
            .bind(user)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        sqlx::query("INSERT INTO auth_security_notifications(realm_id,id,user_id,recipient,kind) VALUES ($1,$2,$3,$4,'email_changed')")
            .bind(realm)
            .bind(Uuid::new_v4())
            .bind(user)
            .bind(&old)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(true)
    }
}
