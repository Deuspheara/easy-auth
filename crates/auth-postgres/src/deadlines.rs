//! Clock caps for already-authorized, locked transaction state. Not authorization.
use crate::unavailable;
use auth_core::{Error, Result};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Database epoch microseconds retain PostgreSQL timestamp precision without a
/// new public date type/dependency. No client can supply this transaction value.
pub(crate) struct Deadline(i64);

impl Deadline {
    /// Caller obtained this expiry from an exact, locked/consumed proof row.
    pub(crate) fn proof(expires_us: i64) -> Self {
        Self(expires_us)
    }

    pub(crate) fn with_proof(self, expires_us: i64) -> Self {
        Self(self.0.min(expires_us))
    }

    /// Caller holds the owner and live, fresh initiating session row locks and
    /// has validated policy. Capture before this transaction revokes/deletes it.
    pub(crate) async fn fresh_session(
        tx: &mut Transaction<'_, Postgres>,
        realm: Uuid,
        user: Uuid,
        session: Uuid,
    ) -> Result<Self> {
        Self::session(tx, realm, user, session, true).await
    }

    /// Caller holds owner then session locks and validated current account policy.
    pub(crate) async fn active_session(
        tx: &mut Transaction<'_, Postgres>,
        realm: Uuid,
        user: Uuid,
        session: Uuid,
    ) -> Result<Self> {
        Self::session(tx, realm, user, session, false).await
    }

    async fn session(
        tx: &mut Transaction<'_, Postgres>,
        realm: Uuid,
        user: Uuid,
        session: Uuid,
        fresh: bool,
    ) -> Result<Self> {
        let cap: i64 = sqlx::query_scalar(
            r#"
            SELECT (extract(epoch FROM least(expires_at,last_seen_at+interval '30 minutes',
                CASE WHEN $4 THEN authenticated_at+interval '5 minutes' ELSE expires_at END))*1000000)::bigint
            FROM auth_sessions WHERE realm_id=$1 AND user_id=$2 AND id=$3 AND revoked_at IS NULL
              AND (NOT $4 OR (isfinite(authenticated_at) AND authenticated_at<=clock_timestamp()))
            "#,
        ).bind(realm).bind(user).bind(session).bind(fresh)
            .fetch_optional(&mut **tx).await.map_err(unavailable)?.ok_or(Error::Unauthorized)?;
        Ok(Self(cap))
    }

    /// Last statement after potentially blocking writes. It reads no table and
    /// takes no row locks; earlier proof/session rows may have been erased by us.
    pub(crate) async fn check(&self, tx: &mut Transaction<'_, Postgres>) -> Result<()> {
        let live: bool = sqlx::query_scalar(
            "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint < $1",
        )
        .bind(self.0)
        .fetch_one(&mut **tx)
        .await
        .map_err(unavailable)?;
        if !live {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}
