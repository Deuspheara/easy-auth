mod listing;
mod ownership;
mod revocation;

use crate::audit;
use auth_core::AuditEvent;

use crate::{Postgres, identity::user_from_row, unavailable};
use auth_core::User;
use auth_core::{Error, Result, Verifier};
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
    pub(crate) async fn revoke(&self, realm: Uuid, session: Verifier) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        // Lock the user before its session: audit ownership checks take user/session key locks.
        let user: Option<Uuid> = sqlx::query_scalar(
            r#"
            SELECT u.id FROM auth_users u
            JOIN auth_sessions s ON s.realm_id=u.realm_id AND s.user_id=u.id
            WHERE s.realm_id=$1 AND s.token_hash=$2 FOR UPDATE OF u
        "#,
        )
        .bind(realm)
        .bind(session.as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?;
        if let Some(user_id) = user {
            let revoked: Option<Uuid> = sqlx::query_scalar(
                r#"
                UPDATE auth_sessions SET revoked_at=statement_timestamp()
                WHERE realm_id=$1 AND token_hash=$2 AND user_id=$3 AND revoked_at IS NULL
                RETURNING id
            "#,
            )
            .bind(realm)
            .bind(session.as_slice())
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(unavailable)?;
            if let Some(session_id) = revoked {
                audit::record(
                    &mut tx,
                    realm,
                    AuditEvent::SessionRevoked {
                        user_id,
                        actor_session_id: session_id,
                        session_id,
                    },
                )
                .await?;
            }
        }
        tx.commit().await.map_err(unavailable)
    }
}
