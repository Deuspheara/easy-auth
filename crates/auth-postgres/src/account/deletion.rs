use crate::locking::{fresh_account, lock_email};
use crate::{Postgres, unavailable};
use auth_core::{Error, Result, Verifier};
use uuid::Uuid;

impl Postgres {
    pub(crate) async fn begin_account_deletion(
        &self,
        realm: Uuid,
        current: Verifier,
        token: Verifier,
        browser: Verifier,
    ) -> Result<String> {
        let email = self.current_email(realm, current).await?;
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        lock_email(&mut tx, realm, &email).await?;
        let (user, session) = fresh_account(&mut tx, realm, current, &email).await?;
        sqlx::query(
            r#"
            INSERT INTO auth_account_deletions(realm_id,user_id,session_id,email,token_hash,browser_hash)
            VALUES ($1,$2,$3,$4,$5,$6)
            "#,
        )
        .bind(realm)
        .bind(user)
        .bind(session)
        .bind(&email)
        .bind(token.as_slice())
        .bind(browser.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(email)
    }
    pub(crate) async fn finish_account_deletion(
        &self,
        realm: Uuid,
        current: Verifier,
        token: Verifier,
        browser: Verifier,
    ) -> Result<()> {
        let email:String=sqlx::query_scalar("SELECT email FROM auth_account_deletions WHERE realm_id=$1 AND token_hash=$2 AND browser_hash=$3")
            .bind(realm)
            .bind(token.as_slice())
            .bind(browser.as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(unavailable)?
            .ok_or(Error::Unauthorized)?;
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        lock_email(&mut tx, realm, &email).await?;
        let (user, session) = fresh_account(&mut tx, realm, current, &email).await?;
        let consumed = sqlx::query(
            r#"
            DELETE
            FROM auth_account_deletions
            WHERE realm_id=$1
            AND token_hash=$2
            AND browser_hash=$3
            AND user_id=$4
            AND session_id=$5
            AND expires_at>clock_timestamp()
            "#,
        )
        .bind(realm)
        .bind(token.as_slice())
        .bind(browser.as_slice())
        .bind(user)
        .bind(session)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        if consumed.rows_affected() != 1 {
            return Err(Error::Unauthorized);
        }
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
        sqlx::query("DELETE FROM auth_rate_buckets WHERE realm_id=$1 AND dimension IN ('email','password_email') AND key_hash=sha256($2)")
            .bind(realm)
            .bind(email.as_bytes())
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        sqlx::query("UPDATE auth_audit SET user_id=NULL WHERE realm_id=$1 AND user_id=$2")
            .bind(realm)
            .bind(user)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        sqlx::query("DELETE FROM auth_users WHERE realm_id=$1 AND id=$2")
            .bind(realm)
            .bind(user)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        sqlx::query(
            "INSERT INTO auth_audit(realm_id,user_id,kind) VALUES ($1,NULL,'account_deleted')",
        )
        .bind(realm)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        sqlx::query("INSERT INTO auth_security_notifications(realm_id,id,user_id,recipient,kind) VALUES ($1,$2,NULL,$3,'account_deleted')")
            .bind(realm)
            .bind(Uuid::new_v4())
            .bind(&email)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)
    }
}
