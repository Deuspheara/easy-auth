use super::setup::Fixture;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::{sync::atomic::Ordering, time::Duration};

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_apple_callbacks_have_one_winner_and_distinct_operations_share_one_subject_owner(
    pool: PgPool,
) {
    let f = Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Allow).await;
    let a = f.prepare("subject", json!({})).await;
    let (first, second) = tokio::join!(f.finish(&a), f.finish(&a));
    let verified = match (first, second) {
        (Ok(v), Err(Error::Unauthorized)) | (Err(Error::Unauthorized), Ok(v)) => v,
        _ => panic!("one successful consume and one explicit replay denial required"),
    };
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
    let b = f.prepare("subject", json!({})).await;
    let other = f.finish(&b).await.unwrap();
    let one = f.policy.map(verified).unwrap();
    let two = f.policy.map(other).unwrap();
    let signin = OidcSignIn::new(f.store.clone());
    let (one, two) = tokio::join!(signin.finish(one), signin.finish(two));
    let (a, first) = one.unwrap();
    let (b, second) = two.unwrap();
    assert_eq!(a, b);
    assert_ne!(first.verifier(), second.verifier());
    assert_eq!(f.facts().await, (1, 1, 2, 2, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn apple_audit_failure_rolls_back_final_authority_without_reviving_consumed_state(
    pool: PgPool,
) {
    let f = Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Allow).await;
    let a = f.prepare("subject", json!({})).await;
    let identity = f.finish(&a).await.unwrap();
    sqlx::raw_sql("CREATE FUNCTION reject_apple_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned Apple audit fault'; END $$; CREATE TRIGGER reject_apple_audit BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION reject_apple_audit();").execute(&f.pool).await.unwrap();
    assert!(matches!(
        OidcSignIn::new(f.store.clone())
            .finish(f.policy.map(identity).unwrap())
            .await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    assert!(matches!(f.finish(&a).await, Err(Error::Unauthorized)));
    sqlx::query("DROP TRIGGER reject_apple_audit ON auth_audit")
        .execute(&f.pool)
        .await
        .unwrap();
    let valid = f.prepare("subject", json!({})).await;
    f.signin(&valid).await.unwrap();
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn source_disable_during_actual_apple_token_post_rejects_late_signed_result(pool: PgPool) {
    let f = Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Allow).await;
    let a = f.prepare("subject", json!({})).await;
    f.provider.hold.store(true, Ordering::SeqCst);
    let flow = f.flow.clone();
    let redirect = f.policy.configuration().redirect().to_owned();
    let action = tokio::spawn(async move {
        flow.finish(
            &a.intent(),
            &a.start.transaction.state,
            a.proof(),
            &redirect,
            a.response(None),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(5), f.provider.entered.notified())
        .await
        .expect("owned token POST entered");
    let c = f.policy.configuration();
    f.store
        .disable_oauth_connection(c.realm(), c.connection(), c.client())
        .await
        .unwrap();
    f.provider.release.notify_one();
    assert!(matches!(action.await.unwrap(), Err(Error::Unauthorized)));
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
}
