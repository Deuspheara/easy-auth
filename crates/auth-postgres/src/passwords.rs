use crate::audit;
use crate::{Postgres, unavailable};
use auth_core::AuditEvent;
use auth_core::{Error, Result, Verifier};
use uuid::Uuid;

impl Postgres {
    pub(crate) async fn admit_password(
        &self,
        realm: Uuid,
        email: &str,
        source: Verifier,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        for (dimension, key, limit) in [
            ("password_email", email.as_bytes(), 10),
            ("password_source", source.as_slice(), 40),
        ] {
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
        tx.commit().await.map_err(unavailable)
    }
    pub(crate) async fn password_hash(&self, realm: Uuid, email: &str) -> Result<Option<String>> {
        sqlx::query_scalar(
            r#"
            SELECT c.password_hash
            FROM auth_password_credentials c
            JOIN auth_users u ON u.realm_id=c.realm_id
            AND u.id=c.user_id
            WHERE u.realm_id=$1
            AND u.email=$2
            AND u.authentication_policy='mailbox'
            "#,
        )
        .bind(realm)
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)
    }
    pub(crate) async fn enroll_password(
        &self,
        realm: Uuid,
        current: Verifier,
        hash: &str,
        replacement: Verifier,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        // Lock user first: all credential mutations serialize here, then revalidate the session.
        let user: Option<Uuid> = sqlx::query_scalar(
            r#"
            SELECT u.id
            FROM auth_users u
            JOIN auth_sessions s ON s.realm_id=u.realm_id
            AND s.user_id=u.id
            WHERE s.realm_id=$1
            AND s.token_hash=$2
            AND u.email IS NOT NULL AND u.authentication_policy='mailbox'
            FOR
            UPDATE OF u
            "#,
        )
        .bind(realm)
        .bind(current.as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?;
        let user = user.ok_or(Error::Unauthorized)?;
        let active: Option<Uuid> = sqlx::query_scalar(
            r#"
            SELECT id
            FROM auth_sessions
            WHERE realm_id=$1
            AND token_hash=$2
            AND revoked_at IS NULL
            AND authenticated_at > clock_timestamp()-interval '5 minutes'
            AND authenticated_at <= clock_timestamp()
            AND expires_at > clock_timestamp()
            AND last_seen_at > clock_timestamp()-interval '30 minutes'
            FOR
            UPDATE
            "#,
        )
        .bind(realm)
        .bind(current.as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?;
        let actor_session_id = active.ok_or(Error::Unauthorized)?;
        let inserted = sqlx::query("INSERT INTO auth_password_credentials(realm_id,user_id,password_hash) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING")
            .bind(realm)
            .bind(user)
            .bind(hash)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        if inserted.rows_affected() != 1 {
            return Err(Error::Unauthorized);
        }
        sqlx::query("UPDATE auth_sessions SET revoked_at=clock_timestamp() WHERE realm_id=$1 AND user_id=$2 AND revoked_at IS NULL")
            .bind(realm)
            .bind(user)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        let session_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO auth_sessions(realm_id,id,user_id,token_hash,authenticated_at,authentication_method) SELECT $1,$2,$3,$4,authenticated_at,authentication_method FROM auth_sessions WHERE realm_id=$1 AND token_hash=$5",
        )
        .bind(realm)
        .bind(session_id)
        .bind(user)
        .bind(replacement.as_slice())
        .bind(current.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        audit::record(
            &mut tx,
            realm,
            AuditEvent::PasswordEnrolled {
                user_id: user,
                actor_session_id,
                session_id,
            },
        )
        .await?;
        tx.commit().await.map_err(unavailable)
    }
    pub(crate) async fn password_login(
        &self,
        realm: Uuid,
        email: &str,
        hash: &str,
        session: Verifier,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let user: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM auth_users WHERE realm_id=$1 AND email=$2 AND authentication_policy='mailbox' FOR UPDATE",
        )
        .bind(realm)
        .bind(email)
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?;
        let user = user.ok_or(Error::Unauthorized)?;
        let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auth_password_credentials WHERE realm_id=$1 AND user_id=$2 AND password_hash=$3)")
            .bind(realm)
            .bind(user)
            .bind(hash)
            .fetch_one(&mut *tx)
            .await
            .map_err(unavailable)?;
        if !valid {
            return Err(Error::Unauthorized);
        }
        let session_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO auth_sessions(realm_id,id,user_id,token_hash,authentication_method) VALUES ($1,$2,$3,$4,'password')",
        )
        .bind(realm)
        .bind(session_id)
        .bind(user)
        .bind(session.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        audit::record(
            &mut tx,
            realm,
            AuditEvent::PasswordAuthenticated {
                user_id: user,
                session_id,
            },
        )
        .await?;
        tx.commit().await.map_err(unavailable)
    }
}
