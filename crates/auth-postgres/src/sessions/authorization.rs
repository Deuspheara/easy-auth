//! Existing fresh-owner authorization reused by outbound consent/code commits.
use super::ownership::Owner;
use crate::{deadlines::Deadline, unavailable};
use auth_core::{Error, Result, Verifier};
use sqlx::{PgExecutor, Postgres, Transaction};
use uuid::Uuid;

/// Read before opening the transaction; this snapshot only selects lock order.
/// It cannot authorize anything until lock() rechecks the actual source/owner.
pub(crate) struct FreshSessionSnapshot {
    owner: Owner,
    realm: Uuid,
    current: Verifier,
}
pub(crate) struct FreshSessionAuthorization {
    pub(crate) user: Uuid,
    pub(crate) session: Uuid,
    pub(crate) authenticated_at_us: i64,
    pub(crate) method: String,
    pub(crate) deadline: Deadline,
}
impl FreshSessionSnapshot {
    pub(crate) async fn load(
        executor: impl PgExecutor<'_>,
        realm: Uuid,
        current: Verifier,
    ) -> Result<Self> {
        Ok(Self {
            owner: Owner::load(executor, realm, current).await?,
            realm,
            current,
        })
    }
    pub(crate) async fn lock(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<FreshSessionAuthorization> {
        let user = self.owner.user;
        let session = self.owner.lock_fresh(tx, self.realm, self.current).await?;
        let (method, authenticated_at_us): (String, i64) = sqlx::query_as(
            "SELECT authentication_method,(extract(epoch FROM authenticated_at)*1000000)::bigint FROM auth_sessions WHERE realm_id=$1 AND user_id=$2 AND id=$3 AND authentication_method IN ('email','password','passkey','oidc','saml')",
        ).bind(self.realm).bind(user).bind(session).fetch_optional(&mut **tx).await
            .map_err(unavailable)?.ok_or(Error::Unauthorized)?;
        let deadline = Deadline::fresh_session(tx, self.realm, user, session).await?;
        Ok(FreshSessionAuthorization {
            user,
            session,
            authenticated_at_us,
            method,
            deadline,
        })
    }
}
