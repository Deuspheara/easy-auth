use crate::{Postgres, identity::user_from_row, unavailable};
use auth_core::{Error, Result, User, Verifier};
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
            AND EXISTS (SELECT 1 FROM auth_users owner
                WHERE owner.realm_id=$1 AND owner.id=auth_sessions.user_id
                  AND (owner.authentication_policy='mailbox'
                    OR (owner.authentication_policy='passkey_required'
                        AND auth_sessions.authentication_method='passkey')))
            RETURNING user_id)
            SELECT u.id,u.email,u.display_name,u.authentication_policy
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
        user_from_row(realm, &row)
    }
}
