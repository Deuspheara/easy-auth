use super::setup::{Fixture, wait_for_lock};
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_distinct_valid_proofs_for_one_subject_create_one_owner(pool: PgPool) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let first = f.mapped("subject", json!({})).await;
    let second = f.mapped("subject", json!({})).await;
    let (first, second) = tokio::join!(f.sign_in.finish(first), f.sign_in.finish(second));
    let (a, one) = first.unwrap();
    let (b, two) = second.unwrap();
    assert_eq!(a, b);
    assert_ne!(one.verifier(), two.verifier());
    for session in [one, two] {
        assert_eq!(
            f.store
                .authenticate(f.realm(), session.verifier())
                .await
                .unwrap(),
            a
        );
    }
    assert_eq!(f.facts().await, (1, 1, 2, 2, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn final_audit_wait_cannot_outlive_original_proof_or_leave_partial_provisioning(
    pool: PgPool,
) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let mapped = f
        .mapped_for("subject", json!({}), OAuthPurpose::SignIn, Some(2))
        .await;
    let cap = mapped.identity().expires_us();
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE auth_audit IN SHARE MODE")
        .execute(&mut *gate)
        .await
        .unwrap();
    let store = f.store.clone();
    let action = tokio::spawn(async move { OidcSignIn::new(store).finish(mapped).await });
    wait_for_lock(&f.pool, "%INSERT INTO auth_audit%").await;
    f.wait_for_expiry(cap).await;
    gate.commit().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), action)
        .await
        .expect("test infrastructure: released callback completes")
        .unwrap();
    assert!(
        matches!(result, Err(Error::Unauthorized)),
        "infrastructure failure cannot prove deadline denial"
    );
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    f.sign_in
        .finish(f.mapped("subject", json!({})).await)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn disable_committing_before_waiting_callback_rejects_all_provisioning(pool: PgPool) {
    let mut f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let mapped = f.mapped("subject", json!({})).await;
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("UPDATE auth_oauth_connections SET enabled=false,revision=$2 WHERE realm_id=$1")
        .bind(f.realm())
        .bind(uuid::Uuid::new_v4())
        .execute(&mut *gate)
        .await
        .unwrap();
    let store = f.store.clone();
    let action = tokio::spawn(async move { OidcSignIn::new(store).finish(mapped).await });
    wait_for_lock(&f.pool, "%FROM auth_oauth_connections WHERE%").await;
    gate.commit().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), action)
        .await
        .expect("test infrastructure: callback released after disable")
        .unwrap();
    assert!(matches!(result, Err(Error::Unauthorized)));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    f.reconfigure(OidcJitPolicy::Allow).await;
    f.store
        .enable_oauth_connection(f.policy.configuration())
        .await
        .unwrap();
    f.sign_in
        .finish(f.mapped("subject", json!({})).await)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn admitted_callback_commits_before_waiting_disable_and_its_session_is_then_unusable(
    pool: PgPool,
) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let mapped = f.mapped("subject", json!({})).await;
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE auth_audit IN SHARE MODE")
        .execute(&mut *gate)
        .await
        .unwrap();
    let store = f.store.clone();
    let callback = tokio::spawn(async move { OidcSignIn::new(store).finish(mapped).await });
    wait_for_lock(&f.pool, "%INSERT INTO auth_audit%").await;
    let store = f.store.clone();
    let c = f.policy.configuration().clone();
    let disable = tokio::spawn(async move {
        store
            .disable_oauth_connection(c.realm(), c.connection(), c.client())
            .await
    });
    wait_for_lock(&f.pool, "%UPDATE auth_oauth_connections SET enabled=false%").await;
    gate.commit().await.unwrap();
    let (_, session) = tokio::time::timeout(Duration::from_secs(5), callback)
        .await
        .expect("test infrastructure: admitted callback finishes")
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), disable)
        .await
        .expect("test infrastructure: waiting disable finishes")
        .unwrap()
        .unwrap();
    assert!(matches!(
        f.store.authenticate(f.realm(), session.verifier()).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
}
