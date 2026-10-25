use super::super::setup::Fixture;
use super::*;
use crate::support::observation as waits;
use serde_json::json;
use sqlx::PgPool;
use std::{sync::atomic::Ordering, time::Duration};

#[sqlx::test(migrations = "./migrations")]
async fn captured_grant_and_all_authority_roll_back_when_original_cap_crosses_actual_audit_wait(
    pool: PgPool,
) {
    let f = Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Allow).await;
    let a = f.prepare("deadline-grant", json!({})).await;
    let cap:i64=sqlx::query_scalar("UPDATE auth_oauth_transactions SET created_at=statement_timestamp()-interval '297 seconds',expires_at=statement_timestamp()+interval '3 seconds' WHERE realm_id=$1 AND state_hash=$2 RETURNING (extract(epoch FROM expires_at)*1000000)::bigint")
        .bind(f.realm()).bind(a.start.transaction.state.verifier().as_slice()).fetch_one(&f.pool).await.unwrap();
    let grant = captured(&f, &a).await.unwrap();
    assert_eq!(grant.identity().identity().expires_us(), cap);
    let observer = waits::observer(&f.pool).await;
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE auth_audit IN SHARE MODE")
        .execute(&mut *gate)
        .await
        .unwrap();
    let store = f.store.clone();
    let action = tokio::spawn(async move { AppleGrantSignIn::new(store).finish(grant).await });
    waits::audit(&observer).await;
    let live: bool =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint<$1")
            .bind(cap)
            .fetch_one(&observer)
            .await
            .unwrap();
    assert!(live);
    assert!(!action.is_finished());
    assert!(envelopes(&f).await.is_empty());
    waits::expired(&observer, cap).await;
    gate.commit().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), action)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(Error::Unauthorized)));
    assert!(envelopes(&f).await.is_empty());
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    observer.close().await;
    sign_in(&f, "valid-after-expiry").await;
}

#[sqlx::test(migrations = "./migrations")]
async fn source_disable_during_actual_token_post_cannot_return_a_capturable_grant(pool: PgPool) {
    let f = Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Allow).await;
    let a = f.prepare("disabled-grant", json!({})).await;
    f.provider.hold.store(true, Ordering::SeqCst);
    let finish = captured(&f, &a);
    let disable = async {
        tokio::time::timeout(Duration::from_secs(5), f.provider.entered.notified())
            .await
            .unwrap();
        let c = f.policy.configuration();
        f.store
            .disable_oauth_connection(c.realm(), c.connection(), c.client())
            .await
            .unwrap();
        f.provider.release.notify_one();
    };
    let (result, ()) = tokio::join!(finish, disable);
    assert!(matches!(result, Err(Error::Unauthorized)));
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
    assert!(envelopes(&f).await.is_empty());
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_captured_callbacks_exchange_and_commit_only_one_grant(pool: PgPool) {
    let f = Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Allow).await;
    let a = f.prepare("concurrent-grant", json!({})).await;
    let (left, right) = tokio::join!(captured(&f, &a), captured(&f, &a));
    let grant = match (left, right) {
        (Ok(grant), Err(Error::Unauthorized)) | (Err(Error::Unauthorized), Ok(grant)) => grant,
        _ => panic!("one consumed callback must win"),
    };
    AppleGrantSignIn::new(f.store.clone())
        .finish(grant)
        .await
        .unwrap();
    assert_eq!(envelopes(&f).await.len(), 1);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
}
