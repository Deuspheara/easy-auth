use crate::{Postgres, unavailable};
use auth_core::{Error, PasskeyManagementRequest, Result};
use uuid::Uuid;

/// Admission is durable even if the later operation fails. This snapshot only
/// selects an abuse bucket, never authorizes management. Use existing shared limits.
pub(super) async fn admit(store: &Postgres, request: &PasskeyManagementRequest) -> Result<()> {
    let user: Uuid =
        sqlx::query_scalar("SELECT user_id FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2")
            .bind(request.realm)
            .bind(request.session.as_slice())
            .fetch_optional(&store.pool)
            .await
            .map_err(unavailable)?
            .ok_or(Error::Unauthorized)?;
    store
        .admit_user_action(request.realm, user, request.source)
        .await
}
