use super::setup::Fixture;
use crate::support::signed_in;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = false)]
async fn identity_migration_preserves_existing_mailbox_and_policy_state_without_inventing_sources(
    pool: PgPool,
) {
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|m| m.version <= 17)
    {
        sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
    }
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let session = signed_in(&f.store, f.realm(), "upgrade@example.test").await;
    let before = f
        .store
        .authenticate(f.realm(), session.verifier())
        .await
        .unwrap();
    sqlx::raw_sql(include_str!(
        "../../../../migrations/0018_oidc_identities_sessions.sql"
    ))
    .execute(&f.pool)
    .await
    .unwrap();
    assert_eq!(
        f.store
            .authenticate(f.realm(), session.verifier())
            .await
            .unwrap(),
        before
    );
    f.store
        .check_oidc_connection(f.policy.configuration())
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_sessions WHERE oidc_identity_id IS NOT NULL OR oidc_revision IS NOT NULL").fetch_one(&f.pool).await.unwrap();
    assert_eq!(count, 0);
    f.sign_in
        .finish(f.mapped("subject", json!({})).await)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn provider_session_source_constraints_reject_missing_provenance_and_another_owner(
    pool: PgPool,
) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let (owner, _) = f
        .sign_in
        .finish(f.mapped("first", json!({})).await)
        .await
        .unwrap();
    let (other, _) = f
        .sign_in
        .finish(f.mapped("second", json!({})).await)
        .await
        .unwrap();
    let identity: Uuid =
        sqlx::query_scalar("SELECT id FROM auth_oidc_identities WHERE realm_id=$1 AND user_id=$2")
            .bind(f.realm())
            .bind(owner.id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    let secret = Secret::generate().unwrap();
    let error = sqlx::query("INSERT INTO auth_sessions(realm_id,id,user_id,token_hash,authentication_method) VALUES($1,$2,$3,$4,'oidc')")
        .bind(f.realm()).bind(Uuid::new_v4()).bind(owner.id).bind(secret.verifier().as_slice()).execute(&f.pool).await.unwrap_err();
    assert_eq!(
        error.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("23514")
    );
    let error = sqlx::query("INSERT INTO auth_sessions(realm_id,id,user_id,token_hash,authentication_method,oidc_identity_id,oidc_revision) VALUES($1,$2,$3,$4,'oidc',$5,$6)")
        .bind(f.realm()).bind(Uuid::new_v4()).bind(other.id).bind(secret.verifier().as_slice()).bind(identity).bind(f.policy.configuration().revision()).execute(&f.pool).await.unwrap_err();
    assert_eq!(
        error.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("23503")
    );
    assert_eq!(f.facts().await, (2, 2, 2, 2, 0));
}
