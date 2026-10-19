use crate::locking::lock_email;
use crate::{Postgres, unavailable};
use crate::{audit, identity::user_from_row};
use auth_core::AuditEvent;
use auth_core::User;
use auth_core::{Error, Result, Verifier};
use sqlx::Row;
use uuid::Uuid;

impl Postgres {
    pub(crate) async fn begin_email(
        &self,
        realm: Uuid,
        email: &str,
        token: Verifier,
        browser: Verifier,
        source: Verifier,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        lock_email(&mut tx, realm, email).await?;
        // Fixed ordering avoids deadlocks; limits are shared across all replicas.
        for (dimension, key, limit) in [
            ("email", email.as_bytes(), 5),
            ("source", source.as_slice(), 20),
        ] {
            // pgcrypto is unnecessary: email is hashed by PostgreSQL's built-in SHA-256.
            let admitted = sqlx::query(
                r#"
                INSERT INTO auth_rate_buckets(realm_id,dimension,key_hash,window_id,attempts)
                VALUES ($1,$2,sha256($3),floor(extract(epoch
                FROM statement_timestamp())/600)::bigint,1)
                ON CONFLICT (realm_id,dimension,key_hash,window_id) DO
                UPDATE
                SET attempts=auth_rate_buckets.attempts+1
                WHERE auth_rate_buckets.attempts < $4
                RETURNING attempts
                "#,
            )
            .bind(realm)
            .bind(dimension)
            .bind(key)
            .bind(limit)
            .fetch_optional(&mut *tx)
            .await
            .map_err(unavailable)?;
            if admitted.is_none() {
                return Err(Error::RateLimited);
            }
        }
        sqlx::query("INSERT INTO auth_email_challenges(realm_id,email,token_hash,browser_hash) VALUES ($1,$2,$3,$4)")
            .bind(realm)
            .bind(email)
            .bind(token.as_slice())
            .bind(browser.as_slice())
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)
    }
    pub(crate) async fn finish_email(
        &self,
        realm: Uuid,
        token: Verifier,
        browser: Verifier,
        session: Verifier,
    ) -> Result<User> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let pending: String = sqlx::query_scalar(
            r#"
            SELECT email
            FROM auth_email_challenges
            WHERE realm_id=$1
            AND token_hash=$2
            AND browser_hash=$3
            AND expires_at>clock_timestamp()
            "#,
        )
        .bind(realm)
        .bind(token.as_slice())
        .bind(browser.as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Unauthorized)?;
        lock_email(&mut tx, realm, &pending).await?;
        let challenge = sqlx::query(
            r#"
            DELETE
            FROM auth_email_challenges
            WHERE realm_id=$1
            AND token_hash=$2
            AND browser_hash=$3
            AND expires_at > statement_timestamp()
            RETURNING email
            "#,
        )
        .bind(realm)
        .bind(token.as_slice())
        .bind(browser.as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Unauthorized)?;
        let email: String = challenge.get("email");
        let row = sqlx::query(
            r#"
            INSERT INTO auth_users(realm_id,id,email)
            VALUES ($1,$2,$3)
            ON CONFLICT (realm_id,email) DO
            UPDATE
            SET email=EXCLUDED.email
            RETURNING id,email,display_name,authentication_policy
            "#,
        )
        .bind(realm)
        .bind(Uuid::new_v4())
        .bind(&email)
        .fetch_one(&mut *tx)
        .await
        .map_err(unavailable)?;
        let user = user_from_row(realm, &row)?;
        if user.authentication_policy != auth_core::AuthenticationPolicy::Mailbox {
            return Err(Error::Unauthorized);
        }
        let session_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO auth_sessions(realm_id,id,user_id,token_hash,authentication_method) VALUES ($1,$2,$3,$4,'email')",
        )
        .bind(realm)
        .bind(session_id)
        .bind(user.id)
        .bind(session.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        audit::record(
            &mut tx,
            realm,
            AuditEvent::EmailAuthenticated {
                user_id: user.id,
                session_id,
            },
        )
        .await?;
        tx.commit().await.map_err(unavailable)?;
        Ok(user)
    }
}
