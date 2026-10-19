use crate::{locking::fresh_session, unavailable};
use auth_core::{Error, Result, Verifier};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

/// Only selects the lock key; freshness and authority are rechecked under locks.
pub(super) async fn lookup(pool: &PgPool, realm: Uuid, current: Verifier) -> Result<Uuid> {
    sqlx::query_scalar("SELECT user_id FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2")
        .bind(realm)
        .bind(current.as_slice())
        .fetch_optional(pool)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Unauthorized)
}

/// Caller already holds the target-email lock. Never acquire email after owner.
pub(super) async fn lock_fresh(
    tx: &mut Transaction<'_, Postgres>,
    realm: Uuid,
    user: Uuid,
    current: Verifier,
) -> Result<Uuid> {
    sqlx::query_scalar::<_, Uuid>(
        r#"
        SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 AND email IS NULL
          AND email_verified_at IS NULL AND authentication_policy='passkey_required'
        FOR UPDATE
        "#,
    )
    .bind(realm)
    .bind(user)
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)?;
    // This locked account's passkey-required policy makes the shared session
    // predicate require an actual passkey method, not just recent creation time.
    fresh_session(tx, realm, user, current).await
}
