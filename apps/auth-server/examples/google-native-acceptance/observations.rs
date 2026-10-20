//! Read-only scoped fixture observations; all grants/writes remain in core/PG.
use super::ProbeResult;
use sqlx::PgPool;
use uuid::Uuid;

pub(super) async fn read(
    pool: &PgPool,
    realm: Uuid,
) -> ProbeResult<(i64, i64, i64, i64, i64, i64)> {
    sqlx::query_as(
        r#"
        SELECT (SELECT count(*) FROM auth_users WHERE realm_id=$1),
          (SELECT count(*) FROM auth_oidc_identities WHERE realm_id=$1),
          (SELECT count(*) FROM auth_sessions WHERE realm_id=$1),
          (SELECT count(*) FROM auth_audit WHERE realm_id=$1),
          (SELECT count(*) FROM auth_oauth_transactions WHERE realm_id=$1),
          (SELECT count(*) FROM auth_sessions WHERE realm_id=$1 AND revoked_at IS NOT NULL)
    "#,
    )
    .bind(realm)
    .fetch_one(pool)
    .await
    .map_err(|_| "observation_storage_unavailable")
}
