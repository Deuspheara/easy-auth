use super::setup::{Fixture, wait_for_lock};
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn provider_validation_and_inventory_reject_disable_committed_during_their_source_lock_wait(
    pool: PgPool,
) {
    for inventory in [false, true] {
        let f = Fixture::new(pool.clone(), OidcJitPolicy::Allow).await;
        let (_, session) = f
            .sign_in
            .finish(f.mapped("subject", json!({})).await)
            .await
            .unwrap();
        let before = f.facts().await;
        let last_seen: i64 = sqlx::query_scalar("SELECT (extract(epoch FROM last_seen_at)*1000000)::bigint FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2")
            .bind(f.realm()).bind(session.verifier().as_slice()).fetch_one(&f.pool).await.unwrap();
        let mut gate = f.pool.begin().await.unwrap();
        sqlx::query(
            "UPDATE auth_oauth_connections SET enabled=false,revision=$2 WHERE realm_id=$1",
        )
        .bind(f.realm())
        .bind(uuid::Uuid::new_v4())
        .execute(&mut *gate)
        .await
        .unwrap();
        let store = f.store.clone();
        let realm = f.realm();
        let current = session.verifier();
        let action = tokio::spawn(async move {
            if inventory {
                store.list_sessions(realm, current, None).await.map(|_| ())
            } else {
                store.authenticate(realm, current).await.map(|_| ())
            }
        });
        wait_for_lock(&f.pool, "%FOR SHARE OF c%").await;
        gate.commit().await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), action)
            .await
            .expect("test infrastructure: disabled-source waiter finishes")
            .unwrap();
        assert!(matches!(result, Err(Error::Unauthorized)));
        assert_eq!(f.facts().await, before);
        let after: i64 = sqlx::query_scalar("SELECT (extract(epoch FROM last_seen_at)*1000000)::bigint FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2")
            .bind(f.realm()).bind(session.verifier().as_slice()).fetch_one(&f.pool).await.unwrap();
        assert_eq!(after, last_seen);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn provider_session_policy_is_revalidated_after_an_observed_owner_wait(pool: PgPool) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let (user, session) = f
        .sign_in
        .finish(f.mapped("subject", json!({})).await)
        .await
        .unwrap();
    let before = f.facts().await;
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("UPDATE auth_users SET authentication_policy='passkey_required' WHERE realm_id=$1 AND id=$2").bind(f.realm()).bind(user.id).execute(&mut *gate).await.unwrap();
    let store = f.store.clone();
    let realm = f.realm();
    let action = tokio::spawn(async move { store.authenticate(realm, session.verifier()).await });
    wait_for_lock(&f.pool, "%FOR SHARE OF u%").await;
    gate.commit().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), action)
        .await
        .expect("test infrastructure: changed-policy owner waiter finishes")
        .unwrap();
    assert!(matches!(result, Err(Error::Unauthorized)));
    assert_eq!(f.facts().await, before);
}
