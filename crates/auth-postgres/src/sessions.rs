use crate::{Postgres, unavailable};
use auth_core::User;
use auth_core::{Error, Result, Verifier};
use sqlx::Row;
use uuid::Uuid;

impl Postgres {
    pub(crate) async fn authenticate(&self, realm: Uuid, session: Verifier) -> Result<User> {
        // Update is conditional, so expiry/revocation cannot be revived by a stale reader.
        let row = sqlx::query(
            r#"
            WITH active AS (UPDATE auth_sessions
            SET last_seen_at=statement_timestamp()
            WHERE realm_id=$1
            AND token_hash=$2
            AND revoked_at IS NULL
            AND expires_at > statement_timestamp()
            AND last_seen_at > statement_timestamp()-interval '30 minutes'
            RETURNING user_id)
            SELECT u.id,u.email
            FROM auth_users u
            JOIN active a ON a.user_id=u.id
            WHERE u.realm_id=$1
            "#,
        )
        .bind(realm)
        .bind(session.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Unauthorized)?;
        Ok(User {
            id: row.get("id"),
            realm_id: realm,
            email: row.get("email"),
        })
    }
    pub(crate) async fn revoke(&self, realm: Uuid, session: Verifier) -> Result<()> {
        sqlx::query(
            r#"
            WITH revoked AS (UPDATE auth_sessions
            SET revoked_at=statement_timestamp()
            WHERE realm_id=$1
            AND token_hash=$2
            AND revoked_at IS NULL
            RETURNING user_id)
            INSERT INTO auth_audit(realm_id,user_id,kind)
            SELECT $1,user_id,'session_revoked'
            FROM revoked
            "#,
        )
        .bind(realm)
        .bind(session.as_slice())
        .execute(&self.pool)
        .await
        .map_err(unavailable)?;
        Ok(())
    }
}
