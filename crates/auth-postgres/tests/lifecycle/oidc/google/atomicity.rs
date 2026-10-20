use super::{setup::Fixture, waits};
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::{sync::atomic::Ordering, time::Duration};

#[sqlx::test(migrations = "./migrations")]
async fn google_final_audit_failure_rolls_back_authority_but_not_consumed_callback(pool: PgPool) {
    let f = Fixture::new(pool, false, OidcJitPolicy::Allow).await;
    let a = f.prepare("subject", json!({}), None).await;
    let mapped = f.policy.map(f.verified(&a).await.unwrap()).unwrap();
    sqlx::raw_sql("CREATE FUNCTION reject_google_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned Google audit fault'; END $$; CREATE TRIGGER reject_google_audit BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION reject_google_audit();")
        .execute(&f.pool).await.expect("test infrastructure: install final audit fault");
    assert!(matches!(f.sign_in(mapped).await, Err(Error::Unavailable)));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    assert!(matches!(f.verified(&a).await, Err(Error::Unauthorized)));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
    sqlx::query("DROP TRIGGER reject_google_audit ON auth_audit")
        .execute(&f.pool)
        .await
        .unwrap();
    f.sign_in(f.mapped("subject", json!({})).await)
        .await
        .unwrap();
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn distinct_verified_google_profile_proofs_serialize_one_subject_without_duplicate_owners(
    pool: PgPool,
) {
    let f = Fixture::new(pool, true, OidcJitPolicy::Allow).await;
    let one = f.mapped("subject", json!({})).await;
    let two = f.mapped("subject", json!({})).await;
    let (one, two) = tokio::join!(f.sign_in(one), f.sign_in(two));
    let (a, first) = one.unwrap();
    let (b, second) = two.unwrap();
    assert_eq!(a, b);
    assert_ne!(first.verifier(), second.verifier());
    assert_eq!(
        f.store
            .authenticate(f.realm(), first.verifier())
            .await
            .unwrap(),
        a
    );
    assert_eq!(
        f.store
            .authenticate(f.realm(), second.verifier())
            .await
            .unwrap(),
        a
    );
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 2);
    assert_eq!(f.facts().await, (1, 1, 2, 2, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn google_proof_expiring_during_observed_final_audit_wait_cannot_commit(pool: PgPool) {
    let f = Fixture::new(pool, false, OidcJitPolicy::Allow).await;
    let a = f.prepare("subject", json!({}), Some(3)).await;
    let identity = f.verified(&a).await.unwrap();
    assert_eq!(identity.expires_us(), a.cap);
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
    let still_live: bool =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint < $1")
            .bind(a.cap)
            .fetch_one(&observer)
            .await
            .unwrap();
    assert!(
        still_live,
        "test infrastructure: action must reach the final wait before its original cap expires"
    );
    assert!(
        !action.is_finished(),
        "no result before the real final commit"
    );
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    waits::expired(&observer, a.cap).await;
    gate.commit().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), action)
        .await
        .expect("test infrastructure: released Google completion")
        .unwrap();
    assert!(
        matches!(result, Err(Error::Unauthorized)),
        "storage failure is not deadline-denial evidence"
    );
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    observer.close().await;
    f.sign_in(f.mapped("subject", json!({})).await)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn disable_during_google_token_response_and_later_revision_changes_reject_old_authority(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool, false, OidcJitPolicy::Allow).await;
    let a = f.prepare("subject", json!({}), None).await;
    let exchange = f.consume(&a).await.unwrap();
    f.provider.hold.store(true, Ordering::SeqCst);
    let client = f.google.clone();
    let code = a.authorization_code();
    let action = tokio::spawn(async move { client.exchange(exchange, code).await });
    tokio::time::timeout(Duration::from_secs(5), f.provider.entered.notified())
        .await
        .expect("test infrastructure: actual Google token POST entered");
    let c = f.policy.configuration();
    f.store
        .disable_oauth_connection(c.realm(), c.connection(), c.client())
        .await
        .unwrap();
    f.provider.hold.store(false, Ordering::SeqCst);
    f.provider.release.notify_one();
    let result = tokio::time::timeout(Duration::from_secs(5), action)
        .await
        .expect("test infrastructure: released Google token response")
        .unwrap();
    assert!(matches!(result, Err(Error::Unauthorized)));
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    f.reconfigure(OidcJitPolicy::Allow).await;
    f.store
        .enable_oauth_connection(f.policy.configuration())
        .await
        .unwrap();
    let old = f.mapped("subject", json!({})).await;
    f.reconfigure(OidcJitPolicy::Allow).await;
    assert!(matches!(f.sign_in(old).await, Err(Error::Unauthorized)));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    f.sign_in(f.mapped("subject", json!({})).await)
        .await
        .unwrap();
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
}
