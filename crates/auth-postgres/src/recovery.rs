use crate::audit;
use crate::locking::lock_email;
use crate::{Postgres, unavailable};
use auth_core::AuditEvent;
use auth_core::{Error, Result, Verifier};
use uuid::Uuid;

impl Postgres {
    pub(crate) async fn begin_password_reset(
        &self,
        realm: Uuid,
        email: &str,
        token: Verifier,
        browser: Verifier,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        lock_email(&mut tx, realm, email).await?;
        sqlx::query(
            r#"
            INSERT INTO auth_password_resets(realm_id,email,token_hash,browser_hash,credential_version)
            VALUES ($1,$2,$3,$4,(SELECT c.version
            FROM auth_password_credentials c
            JOIN auth_users u ON u.realm_id=c.realm_id
            AND u.id=c.user_id
            WHERE u.realm_id=$1
            AND u.email=$2 AND u.authentication_policy='mailbox'))
            "#,
        )
        .bind(realm)
        .bind(email)
        .bind(token.as_slice())
        .bind(browser.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)
    }
    pub(crate) async fn password_reset_email(
        &self,
        realm: Uuid,
        token: Verifier,
        browser: Verifier,
    ) -> Result<String> {
        sqlx::query_scalar(
            r#"
            SELECT r.email
            FROM auth_password_resets r
            JOIN auth_users u ON u.realm_id=r.realm_id
            AND u.email=r.email
            JOIN auth_password_credentials c ON c.realm_id=u.realm_id
            AND c.user_id=u.id
            AND c.version=r.credential_version
            WHERE r.realm_id=$1
            AND r.token_hash=$2
            AND r.browser_hash=$3
            AND r.expires_at>clock_timestamp()
            AND u.authentication_policy='mailbox'
            "#,
        )
        .bind(realm)
        .bind(token.as_slice())
        .bind(browser.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Unauthorized)
    }
    pub(crate) async fn finish_password_reset(
        &self,
        realm: Uuid,
        token: Verifier,
        browser: Verifier,
        hash: &str,
    ) -> Result<()> {
        let email = self.password_reset_email(realm, token, browser).await?;
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        lock_email(&mut tx, realm, &email).await?;
        let user: Uuid = sqlx::query_scalar(
            "SELECT id FROM auth_users WHERE realm_id=$1 AND email=$2 AND authentication_policy='mailbox' FOR UPDATE",
        )
        .bind(realm)
        .bind(&email)
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Unauthorized)?;
        // Revalidate after locks: an earlier preflight or KDF does not authorize a stale proof.
        let consumed = sqlx::query(
            r#"
            DELETE
            FROM auth_password_resets r
            USING auth_password_credentials c
            WHERE r.realm_id=$1
            AND r.token_hash=$2
            AND r.browser_hash=$3
            AND r.email=$4
            AND r.expires_at>clock_timestamp()
            AND c.realm_id=r.realm_id
            AND c.user_id=$5
            AND c.version=r.credential_version
            "#,
        )
        .bind(realm)
        .bind(token.as_slice())
        .bind(browser.as_slice())
        .bind(&email)
        .bind(user)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        if consumed.rows_affected() != 1 {
            return Err(Error::Unauthorized);
        }
        sqlx::query("UPDATE auth_password_credentials SET password_hash=$3, version=$4 WHERE realm_id=$1 AND user_id=$2")
            .bind(realm)
            .bind(user)
            .bind(hash)
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
        sqlx::query("DELETE FROM auth_password_resets WHERE realm_id=$1 AND email=$2")
            .bind(realm)
            .bind(&email)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        sqlx::query("DELETE FROM auth_email_challenges WHERE realm_id=$1 AND email=$2")
            .bind(realm)
            .bind(&email)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
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
        audit::record(&mut tx, realm, AuditEvent::PasswordReset { user_id: user }).await?;
        sqlx::query("INSERT INTO auth_security_notifications(realm_id,id,user_id,recipient) VALUES ($1,$2,$3,$4)")
            .bind(realm)
            .bind(Uuid::new_v4())
            .bind(user)
            .bind(&email)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)
    }
}
