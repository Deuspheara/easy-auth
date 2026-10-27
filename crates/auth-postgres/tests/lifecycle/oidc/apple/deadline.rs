use super::setup::Fixture;
use crate::support::observation as waits;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn original_apple_deadline_crossed_during_observed_final_audit_wait_rolls_back_authority(
    pool: PgPool,
) {
    let f = Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Allow).await;
    let a = f.prepare("subject", json!({})).await;
    let original_window: bool = sqlx::query_scalar("SELECT expires_at-created_at=interval '5 minutes' FROM auth_oauth_transactions WHERE realm_id=$1 AND state_hash=$2")
        .bind(f.realm()).bind(a.start.transaction.state.verifier().as_slice()).fetch_one(&f.pool).await.unwrap();
    assert!(original_window);
    // Arrange a near-expiry owned operation while retaining its complete original
    // five-minute interval. Never modify a server policy or extend a deadline.
    let cap: i64 = sqlx::query_scalar("UPDATE auth_oauth_transactions SET created_at=statement_timestamp()-interval '297 seconds',expires_at=statement_timestamp()+interval '3 seconds' WHERE realm_id=$1 AND state_hash=$2 RETURNING (extract(epoch FROM expires_at)*1000000)::bigint")
        .bind(f.realm()).bind(a.start.transaction.state.verifier().as_slice()).fetch_one(&f.pool).await.unwrap();
    let identity = f.finish(&a).await.unwrap();
    assert_eq!(identity.expires_us(), cap);
    let mapped = f.policy.map(identity).unwrap();
    let observer = waits::observer(&f.pool).await;
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE auth_audit IN SHARE MODE")
        .execute(&mut *gate)
        .await
        .unwrap();
    let store = f.store.clone();
    let action = tokio::spawn(async move { OidcSignIn::new(store).finish(mapped).await });
    waits::audit(&observer).await;
    let live: bool =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint < $1")
            .bind(cap)
            .fetch_one(&observer)
            .await
            .unwrap();
    assert!(
        live,
        "owned completion must reach its actual audit wait before expiry"
    );
    assert!(!action.is_finished());
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    waits::expired(&observer, cap).await;
    gate.commit().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), action)
        .await
        .expect("released owned audit waiter")
        .unwrap();
    assert!(matches!(result, Err(Error::Unauthorized)));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    observer.close().await;
    let valid = f.prepare("subject", json!({})).await;
    f.signin(&valid).await.unwrap();
}
