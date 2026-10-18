//! PostgreSQL transactions for the shared core. SQL row shapes are private.
use async_trait::async_trait;
use auth_core::{Error, Repository, Result, User, Verifier};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Clone)]
pub struct Postgres {
    pool: PgPool,
}
fn unavailable(_: sqlx::Error) -> Error {
    Error::Unavailable
}
impl Postgres {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!()
            .run(&self.pool)
            .await
            .map_err(|_| Error::Unavailable)
    }
    /// Only trusted startup configuration provisions realms, never request input.
    pub async fn ensure_realm(&self, realm: Uuid) -> Result<()> {
        sqlx::query("INSERT INTO auth_realms(id) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(realm)
            .execute(&self.pool)
            .await
            .map_err(unavailable)?;
        Ok(())
    }
}
#[async_trait]
impl Repository for Postgres {
    async fn begin_email(
        &self,
        realm: Uuid,
        email: &str,
        token: Verifier,
        browser: Verifier,
        source: Verifier,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        // Fixed ordering avoids deadlocks; limits are shared across all replicas.
        for (dimension, key, limit) in [
            ("email", email.as_bytes(), 5),
            ("source", source.as_slice(), 20),
        ] {
            // pgcrypto is unnecessary: email is hashed by PostgreSQL's built-in SHA-256.
            let admitted = sqlx::query("INSERT INTO auth_rate_buckets(realm_id,dimension,key_hash,window_id,attempts) VALUES ($1,$2,sha256($3),floor(extract(epoch FROM statement_timestamp())/600)::bigint,1) ON CONFLICT (realm_id,dimension,key_hash,window_id) DO UPDATE SET attempts=auth_rate_buckets.attempts+1 WHERE auth_rate_buckets.attempts < $4 RETURNING attempts")
                .bind(realm).bind(dimension).bind(key).bind(limit).fetch_optional(&mut *tx).await.map_err(unavailable)?;
            if admitted.is_none() {
                return Err(Error::RateLimited);
            }
        }
        sqlx::query("INSERT INTO auth_email_challenges(realm_id,email,token_hash,browser_hash) VALUES ($1,$2,$3,$4)")
            .bind(realm).bind(email).bind(token.as_slice()).bind(browser.as_slice()).execute(&mut *tx).await.map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)
    }
    async fn finish_email(
        &self,
        realm: Uuid,
        token: Verifier,
        browser: Verifier,
        session: Verifier,
    ) -> Result<User> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let challenge = sqlx::query("DELETE FROM auth_email_challenges WHERE realm_id=$1 AND token_hash=$2 AND browser_hash=$3 AND expires_at > statement_timestamp() RETURNING email")
            .bind(realm).bind(token.as_slice()).bind(browser.as_slice()).fetch_optional(&mut *tx).await.map_err(unavailable)?
            .ok_or(Error::Unauthorized)?;
        let email: String = challenge.get("email");
        let row = sqlx::query("INSERT INTO auth_users(realm_id,id,email) VALUES ($1,$2,$3) ON CONFLICT (realm_id,email) DO UPDATE SET email=EXCLUDED.email RETURNING id")
            .bind(realm).bind(Uuid::new_v4()).bind(&email).fetch_one(&mut *tx).await.map_err(unavailable)?;
        let user = User {
            id: row.get("id"),
            realm_id: realm,
            email,
        };
        sqlx::query(
            "INSERT INTO auth_sessions(realm_id,id,user_id,token_hash) VALUES ($1,$2,$3,$4)",
        )
        .bind(realm)
        .bind(Uuid::new_v4())
        .bind(user.id)
        .bind(session.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        sqlx::query(
            "INSERT INTO auth_audit(realm_id,user_id,kind) VALUES ($1,$2,'email_authenticated')",
        )
        .bind(realm)
        .bind(user.id)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(user)
    }
    async fn authenticate(&self, realm: Uuid, session: Verifier) -> Result<User> {
        // Update is conditional, so expiry/revocation cannot be revived by a stale reader.
        let row = sqlx::query("WITH active AS (UPDATE auth_sessions SET last_seen_at=statement_timestamp() WHERE realm_id=$1 AND token_hash=$2 AND revoked_at IS NULL AND expires_at > statement_timestamp() AND last_seen_at > statement_timestamp()-interval '30 minutes' RETURNING user_id) SELECT u.id,u.email FROM auth_users u JOIN active a ON a.user_id=u.id WHERE u.realm_id=$1")
            .bind(realm).bind(session.as_slice()).fetch_optional(&self.pool).await.map_err(unavailable)?.ok_or(Error::Unauthorized)?;
        Ok(User {
            id: row.get("id"),
            realm_id: realm,
            email: row.get("email"),
        })
    }
    async fn revoke(&self, realm: Uuid, session: Verifier) -> Result<()> {
        sqlx::query("WITH revoked AS (UPDATE auth_sessions SET revoked_at=statement_timestamp() WHERE realm_id=$1 AND token_hash=$2 AND revoked_at IS NULL RETURNING user_id) INSERT INTO auth_audit(realm_id,user_id,kind) SELECT $1,user_id,'session_revoked' FROM revoked")
            .bind(realm).bind(session.as_slice()).execute(&self.pool).await.map_err(unavailable)?;
        Ok(())
    }
    async fn admit_password(&self, realm: Uuid, email: &str, source: Verifier) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        for (dimension, key, limit) in [
            ("password_email", email.as_bytes(), 10),
            ("password_source", source.as_slice(), 40),
        ] {
            let admitted = sqlx::query("INSERT INTO auth_rate_buckets(realm_id,dimension,key_hash,window_id,attempts) VALUES ($1,$2,sha256($3),floor(extract(epoch FROM statement_timestamp())/600)::bigint,1) ON CONFLICT (realm_id,dimension,key_hash,window_id) DO UPDATE SET attempts=auth_rate_buckets.attempts+1 WHERE auth_rate_buckets.attempts < $4 RETURNING attempts")
                .bind(realm).bind(dimension).bind(key).bind(limit).fetch_optional(&mut *tx).await.map_err(unavailable)?;
            if admitted.is_none() {
                return Err(Error::RateLimited);
            }
        }
        tx.commit().await.map_err(unavailable)
    }
    async fn password_hash(&self, realm: Uuid, email: &str) -> Result<Option<String>> {
        sqlx::query_scalar("SELECT c.password_hash FROM auth_password_credentials c JOIN auth_users u ON u.realm_id=c.realm_id AND u.id=c.user_id WHERE u.realm_id=$1 AND u.email=$2")
            .bind(realm).bind(email).fetch_optional(&self.pool).await.map_err(unavailable)
    }
    async fn enroll_password(
        &self,
        realm: Uuid,
        current: Verifier,
        hash: &str,
        replacement: Verifier,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        // Lock user first: all credential mutations serialize here, then revalidate the session.
        let user: Option<Uuid> = sqlx::query_scalar("SELECT u.id FROM auth_users u JOIN auth_sessions s ON s.realm_id=u.realm_id AND s.user_id=u.id WHERE s.realm_id=$1 AND s.token_hash=$2 FOR UPDATE OF u")
            .bind(realm).bind(current.as_slice()).fetch_optional(&mut *tx).await.map_err(unavailable)?;
        let user = user.ok_or(Error::Unauthorized)?;
        let active: Option<Uuid> = sqlx::query_scalar("SELECT id FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2 AND revoked_at IS NULL AND created_at > clock_timestamp()-interval '5 minutes' AND expires_at > clock_timestamp() AND last_seen_at > clock_timestamp()-interval '30 minutes' FOR UPDATE")
            .bind(realm).bind(current.as_slice()).fetch_optional(&mut *tx).await.map_err(unavailable)?;
        active.ok_or(Error::Unauthorized)?;
        let inserted = sqlx::query("INSERT INTO auth_password_credentials(realm_id,user_id,password_hash) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING")
            .bind(realm).bind(user).bind(hash).execute(&mut *tx).await.map_err(unavailable)?;
        if inserted.rows_affected() != 1 {
            return Err(Error::Unauthorized);
        }
        sqlx::query("UPDATE auth_sessions SET revoked_at=clock_timestamp() WHERE realm_id=$1 AND user_id=$2 AND revoked_at IS NULL")
            .bind(realm).bind(user).execute(&mut *tx).await.map_err(unavailable)?;
        sqlx::query(
            "INSERT INTO auth_sessions(realm_id,id,user_id,token_hash) VALUES ($1,$2,$3,$4)",
        )
        .bind(realm)
        .bind(Uuid::new_v4())
        .bind(user)
        .bind(replacement.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        sqlx::query(
            "INSERT INTO auth_audit(realm_id,user_id,kind) VALUES ($1,$2,'password_enrolled')",
        )
        .bind(realm)
        .bind(user)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)
    }
    async fn password_login(
        &self,
        realm: Uuid,
        email: &str,
        hash: &str,
        session: Verifier,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let user: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM auth_users WHERE realm_id=$1 AND email=$2 FOR UPDATE",
        )
        .bind(realm)
        .bind(email)
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?;
        let user = user.ok_or(Error::Unauthorized)?;
        let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auth_password_credentials WHERE realm_id=$1 AND user_id=$2 AND password_hash=$3)")
            .bind(realm).bind(user).bind(hash).fetch_one(&mut *tx).await.map_err(unavailable)?;
        if !valid {
            return Err(Error::Unauthorized);
        }
        sqlx::query(
            "INSERT INTO auth_sessions(realm_id,id,user_id,token_hash) VALUES ($1,$2,$3,$4)",
        )
        .bind(realm)
        .bind(Uuid::new_v4())
        .bind(user)
        .bind(session.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        sqlx::query(
            "INSERT INTO auth_audit(realm_id,user_id,kind) VALUES ($1,$2,'password_authenticated')",
        )
        .bind(realm)
        .bind(user)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)
    }
    async fn ready(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(unavailable)?;
        Ok(())
    }
}
