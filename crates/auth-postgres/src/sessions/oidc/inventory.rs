use crate::unavailable;
use auth_core::Result;
use sqlx::{Postgres, Transaction, postgres::PgRow};
use uuid::Uuid;

pub(in crate::sessions) async fn list(
    tx: &mut Transaction<'_, Postgres>,
    realm: Uuid,
    owner: Uuid,
    current: Uuid,
    after: Option<Uuid>,
    limit: i64,
    linked_only: bool,
) -> Result<Vec<PgRow>> {
    sqlx::query(r#"
        SELECT s.id,s.id=$3 AS current,
            floor(extract(epoch FROM s.created_at)*1000)::bigint AS created_at_ms,
            floor(extract(epoch FROM s.last_seen_at)*1000)::bigint AS last_seen_at_ms,
            floor(extract(epoch FROM s.expires_at)*1000)::bigint AS expires_at_ms,
            floor(extract(epoch FROM least(s.expires_at,s.last_seen_at+interval '30 minutes'))*1000)::bigint AS idle_expires_at_ms,
            CASE WHEN isfinite(s.authenticated_at) THEN floor(extract(epoch FROM s.authenticated_at)*1000)::bigint ELSE NULL END AS authenticated_at_ms
        FROM auth_sessions s
        JOIN auth_oidc_identities e ON e.realm_id=s.realm_id AND e.id=s.oidc_identity_id AND e.user_id=s.user_id
        JOIN auth_oauth_connections c ON c.realm_id=e.realm_id AND c.id=e.connection_id AND c.client_id=e.client_id
        JOIN auth_oidc_identity_policies p ON p.realm_id=c.realm_id AND p.connection_id=c.id AND p.client_id=c.client_id
        WHERE s.realm_id=$1 AND s.user_id=$2 AND s.authentication_method='oidc' AND s.revoked_at IS NULL
          AND s.expires_at>statement_timestamp() AND s.last_seen_at>statement_timestamp()-interval '30 minutes'
          AND c.enabled AND c.revision=s.oidc_revision AND p.revision=c.revision AND e.issuer=c.issuer
          AND (NOT $6::boolean OR e.explicitly_linked)
          AND ($4::uuid IS NULL OR s.id>$4)
        ORDER BY s.id LIMIT $5
    "#)
        .bind(realm)
        .bind(owner)
        .bind(current)
        .bind(after)
        .bind(limit)
        .bind(linked_only)
        .fetch_all(&mut **tx)
        .await
        .map_err(unavailable)
}
