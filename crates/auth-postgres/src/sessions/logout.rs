use crate::{Postgres, audit, unavailable};
use auth_core::{AuditEvent, Result, Verifier};
use uuid::Uuid;

impl Postgres {
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
