use crate::{Postgres, unavailable};
use auth_core::{Error, Result, Verifier};
use uuid::Uuid;

/// Admission is durable even if the later operation fails. This snapshot only
/// selects an abuse bucket, never authorizes management. Use existing shared limits.
pub(super) async fn admit_sensitive_action(
    store: &Postgres,
    realm: Uuid,
    current: Verifier,
    source: Verifier,
) -> Result<()> {
    let user: Uuid =
        sqlx::query_scalar("SELECT user_id FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2")
            .bind(realm)
            .bind(current.as_slice())
            .fetch_optional(&store.pool)
            .await
            .map_err(unavailable)?
            .ok_or(Error::Unauthorized)?;
    store.admit_user_action(realm, user, source).await
}
