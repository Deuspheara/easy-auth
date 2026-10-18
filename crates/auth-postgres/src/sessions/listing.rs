use crate::{Postgres, unavailable};
use auth_core::{Error, Result, SessionInfo, SessionPage, Verifier};
use sqlx::Row;
use uuid::Uuid;

const PAGE_SIZE: usize = 50;

impl Postgres {
    pub(crate) async fn list_sessions(
        &self,
        realm: Uuid,
        current: Verifier,
        after: Option<Uuid>,
    ) -> Result<SessionPage> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        // Touch only the caller, conditionally: an expired or revoked session cannot be revived.
        let caller = sqlx::query(
            r#"
            UPDATE auth_sessions SET last_seen_at=statement_timestamp()
            WHERE realm_id=$1 AND token_hash=$2 AND revoked_at IS NULL
              AND expires_at>statement_timestamp()
              AND last_seen_at>statement_timestamp()-interval '30 minutes'
            RETURNING id,user_id
            "#,
        )
        .bind(realm)
        .bind(current.as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Unauthorized)?;
        let current_id: Uuid = caller.get("id");
        let rows = sqlx::query(r#"
            SELECT id,id=$3 AS current,
                floor(extract(epoch FROM created_at)*1000)::bigint AS created_at_ms,
                floor(extract(epoch FROM last_seen_at)*1000)::bigint AS last_seen_at_ms,
                floor(extract(epoch FROM expires_at)*1000)::bigint AS expires_at_ms,
                floor(extract(epoch FROM least(expires_at,last_seen_at+interval '30 minutes'))*1000)::bigint AS idle_expires_at_ms,
                CASE WHEN isfinite(authenticated_at)
                    THEN floor(extract(epoch FROM authenticated_at)*1000)::bigint
                    ELSE NULL END AS authenticated_at_ms
            FROM auth_sessions
            WHERE realm_id=$1 AND user_id=$2 AND revoked_at IS NULL
              AND expires_at>statement_timestamp()
              AND last_seen_at>statement_timestamp()-interval '30 minutes'
              AND ($4::uuid IS NULL OR id>$4)
            ORDER BY id LIMIT $5
        "#)
            .bind(realm)
            .bind(caller.get::<Uuid,_>("user_id"))
            .bind(current_id)
            .bind(after)
            .bind((PAGE_SIZE+1) as i64)
            .fetch_all(&mut *tx)
            .await
            .map_err(unavailable)?;
        let more = rows.len() > PAGE_SIZE;
        let sessions: Vec<SessionInfo> = rows
            .into_iter()
            .take(PAGE_SIZE)
            .map(|row| SessionInfo {
                id: row.get("id"),
                current: row.get("current"),
                created_at_ms: row.get("created_at_ms"),
                last_seen_at_ms: row.get("last_seen_at_ms"),
                expires_at_ms: row.get("expires_at_ms"),
                idle_expires_at_ms: row.get("idle_expires_at_ms"),
                authenticated_at_ms: row.get("authenticated_at_ms"),
            })
            .collect();
        let next = if more {
            sessions.last().map(|s| s.id)
        } else {
            None
        };
        tx.commit().await.map_err(unavailable)?;
        Ok(SessionPage { sessions, next })
    }
}
