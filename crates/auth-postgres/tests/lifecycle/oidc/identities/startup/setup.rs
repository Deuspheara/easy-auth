use crate::support::realm;
use auth_core::*;
use easy_auth_postgres::Postgres;
use serde_json::Value;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

pub(super) async fn empty(pool: PgPool) -> (Arc<Postgres>, OidcIdentityPolicy) {
    let (store, realm) = realm(pool).await;
    (
        Arc::new(store),
        definition(realm, Uuid::new_v4(), Uuid::new_v4()),
    )
}
pub(super) fn definition(realm: Uuid, connection: Uuid, client: Uuid) -> OidcIdentityPolicy {
    let c = OAuthConnection::new(
        realm,
        connection,
        client,
        "https://issuer.example",
        "provider-client",
        &format!("https://app.example/callback/{realm}/{connection}/{client}"),
        OAuthMixupDefense::RequireIssuer,
    )
    .unwrap();
    OidcIdentityPolicy::new(
        c,
        &["https://issuer.example"],
        OidcDisplayNameClaim::Subject,
    )
    .unwrap()
}

/// Compare privately: never print row data, session verifiers or pending proofs.
pub(super) async fn snapshot(pool: &PgPool) -> Value {
    sqlx::query_scalar(r#"SELECT jsonb_build_object(
        'connections',(SELECT jsonb_agg(to_jsonb(t) ORDER BY realm_id,id,client_id) FROM auth_oauth_connections t),
        'policies',(SELECT jsonb_agg(to_jsonb(t) ORDER BY realm_id,connection_id,client_id) FROM auth_oidc_identity_policies t),
        'pending',(SELECT jsonb_agg(to_jsonb(t) ORDER BY realm_id,state_hash) FROM auth_oauth_transactions t),
        'users',(SELECT jsonb_agg(to_jsonb(t) ORDER BY realm_id,id) FROM auth_users t),
        'identities',(SELECT jsonb_agg(to_jsonb(t) ORDER BY realm_id,id) FROM auth_oidc_identities t),
        'sessions',(SELECT jsonb_agg(to_jsonb(t) ORDER BY realm_id,id) FROM auth_sessions t),
        'audit',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM auth_audit t))"#)
        .fetch_one(pool).await.expect("test infrastructure: private startup snapshot")
}
pub(super) async fn counts(pool: &PgPool) -> (i64, i64, i64, i64, i64) {
    sqlx::query_as("SELECT (SELECT count(*) FROM auth_oauth_connections),(SELECT count(*) FROM auth_oidc_identity_policies),(SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_oauth_transactions)")
        .fetch_one(pool).await.expect("test infrastructure: startup counts")
}
