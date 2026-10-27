use super::setup::*;
use crate::support::observation as waits;
use sqlx::PgPool;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn link_rejects_original_proof_expiry_after_an_independently_observed_final_audit_wait(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let (owner, current) = f.local("owner@example.test").await;
    let a = f
        .prepare(
            OAuthPurpose::Link {
                user: owner.id,
                session: current.verifier(),
            },
            "subject",
            json!({}),
        )
        .await;
    // Arrange near expiry without extending or shortening the five-minute window.
    let cap:i64=sqlx::query_scalar("UPDATE auth_oauth_transactions SET created_at=statement_timestamp()-interval '297 seconds',expires_at=statement_timestamp()+interval '3 seconds' WHERE realm_id=$1 AND state_hash=$2 RETURNING (extract(epoch FROM expires_at)*1000000)::bigint")
        .bind(f.realm()).bind(a.start.transaction.state.verifier().as_slice()).fetch_one(&f.pool).await.unwrap();
    let window:bool=sqlx::query_scalar("SELECT expires_at-created_at=interval '5 minutes' FROM auth_oauth_transactions WHERE realm_id=$1 AND state_hash=$2").bind(f.realm()).bind(a.start.transaction.state.verifier().as_slice()).fetch_one(&f.pool).await.unwrap();
    assert!(window);
    let mapped = f.complete(&a).await.unwrap();
    assert_eq!(mapped.identity().expires_us(), cap);
    let before = f.facts().await;
    let observer = waits::observer(&f.pool).await;
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE auth_audit IN SHARE MODE")
        .execute(&mut *gate)
        .await
        .unwrap();
    let store = f.store.clone();
    let action = tokio::spawn(async move {
        OidcIdentityLinking::new(store)
            .finish(mapped, &current)
            .await
    });
    waits::audit(&observer).await;
    let live: bool =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint<$1")
            .bind(cap)
            .fetch_one(&observer)
            .await
            .unwrap();
    assert!(live, "actual final audit wait entered before original cap");
    assert!(!action.is_finished());
    waits::expired(&observer, cap).await;
    gate.commit().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), action)
        .await
        .expect("released actual link audit wait")
        .unwrap();
    assert!(matches!(result, Err(Error::Unauthorized)));
    assert_eq!(f.facts().await, before);
    observer.close().await;
    let (_, fresh) = f.local("owner@example.test").await;
    f.linked(&owner, &fresh, "subject").await;
}

#[sqlx::test(migrations = "./migrations")]
async fn unlink_restores_binding_sessions_and_audit_when_retained_session_expires_during_notice_wait(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let (owner, current) = f.local("owner@example.test").await;
    let linked = f.linked(&owner, &current, "subject").await;
    let (_, provider_session) = f.login("subject").await.unwrap();
    // Shorten an owned absolute deadline; never extend authentication freshness.
    let cap:i64=sqlx::query_scalar("UPDATE auth_sessions SET expires_at=clock_timestamp()+interval '3 seconds' WHERE realm_id=$1 AND token_hash=$2 RETURNING (extract(epoch FROM expires_at)*1000000)::bigint")
        .bind(f.realm()).bind(current.verifier().as_slice()).fetch_one(&f.pool).await.unwrap();
    let before = f.facts().await;
    let observer = waits::observer(&f.pool).await;
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE auth_security_notifications IN SHARE MODE")
        .execute(&mut *gate)
        .await
        .unwrap();
    let store = f.store.clone();
    let realm = f.realm();
    let action = tokio::spawn(async move {
        OidcIdentityLinking::new(store)
            .unlink(realm, &current, linked.id)
            .await
    });
    waits::locked(&observer, "%INSERT INTO auth_security_notifications%").await;
    let live: bool =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint<$1")
            .bind(cap)
            .fetch_one(&observer)
            .await
            .unwrap();
    assert!(
        live,
        "actual final notice wait entered before retained-session cap"
    );
    assert!(!action.is_finished());
    waits::expired(&observer, cap).await;
    gate.commit().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), action)
        .await
        .expect("released actual unlink notice wait")
        .unwrap();
    assert!(matches!(result, Err(Error::Unauthorized)));
    assert_eq!(f.facts().await, before);
    observer.close().await;
    assert_eq!(
        f.store
            .authenticate(f.realm(), provider_session.verifier())
            .await
            .unwrap(),
        owner
    );
    let (_, fresh) = f.local("owner@example.test").await;
    f.linking
        .unlink(f.realm(), &fresh, linked.id)
        .await
        .unwrap();
}
