use super::{delivery, setup::Fixture, waits};
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::atomic::Ordering,
    time::Duration,
};

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn native_actual_signed_nonce_rejection_and_token_transport_failure_are_distinct_and_one_use(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool, IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    let a = f
        .begin(json!({"nonce":Secret::generate().unwrap().expose()}), None)
        .await;
    let captured = delivery::capture(&mut f, &a, None).await;
    assert!(matches!(
        delivery::finish(&f, &a, captured).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(
        f.provider.signed.load(Ordering::SeqCst),
        1,
        "real signed response preceded denial"
    );
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    f.rebind().await;
    let a = f.begin(json!({}), None).await;
    let captured = delivery::capture(&mut f, &a, None).await;
    f.provider.unavailable.store(true, Ordering::SeqCst);
    assert!(matches!(
        delivery::finish(&f, &a, captured).await,
        Err(Error::Unavailable)
    ));
    f.provider.unavailable.store(false, Ordering::SeqCst);
    assert!(matches!(
        f.service
            .finish(
                &a.intent(),
                a.state(),
                a.proof(),
                f.policy.configuration().redirect(),
                a.replay_response()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    f.rebind().await;
    let a = f.begin(json!({}), None).await;
    let captured = delivery::capture(&mut f, &a, None).await;
    f.commit(delivery::finish(&f, &a, captured).await.unwrap())
        .await;
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 3);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 2);
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
}

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn native_final_audit_fault_rolls_back_local_authority_without_restoring_consumed_return(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool, IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    let a = f.begin(json!({}), None).await;
    let captured = delivery::capture(&mut f, &a, None).await;
    let mapped = f.mapped(delivery::finish(&f, &a, captured).await.unwrap());
    sqlx::raw_sql("CREATE FUNCTION owned_native_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned native final audit fault'; END $$; CREATE TRIGGER owned_native_audit_fault BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION owned_native_audit_fault()")
        .execute(&f.pool).await.expect("test infrastructure: actual final-audit fault");
    assert!(matches!(
        OidcSignIn::new(f.store.clone()).finish(mapped).await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    assert!(matches!(
        f.service
            .finish(
                &a.intent(),
                a.state(),
                a.proof(),
                f.policy.configuration().redirect(),
                a.replay_response()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
    sqlx::raw_sql("DROP TRIGGER owned_native_audit_fault ON auth_audit; DROP FUNCTION owned_native_audit_fault()")
        .execute(&f.pool).await.expect("test infrastructure: remove actual final-audit fault");
    f.rebind().await;
    let a = f.begin(json!({}), None).await;
    let captured = delivery::capture(&mut f, &a, None).await;
    f.commit(delivery::finish(&f, &a, captured).await.unwrap())
        .await;
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 2);
}

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn native_original_proof_expiry_during_observed_final_audit_wait_rolls_back_commit(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool, IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    let a = f.begin(json!({}), Some(3)).await;
    let captured = delivery::capture(&mut f, &a, None).await;
    let completion = delivery::finish(&f, &a, captured).await.unwrap();
    let GoogleAuthorizationCompletion::Verified(identity) = &completion else {
        panic!("actual native signed proof required");
    };
    assert_eq!(
        identity.expires_us(),
        a.cap,
        "native receipt/verification cannot restart original cap"
    );
    let mapped = f.mapped(completion);
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
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint<$1")
            .bind(a.cap)
            .fetch_one(&observer)
            .await
            .unwrap();
    assert!(
        still_live,
        "test infrastructure: actual final wait must precede original deadline"
    );
    assert!(!action.is_finished());
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    waits::expired(&observer, a.cap).await;
    gate.commit().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), action)
        .await
        .expect("test infrastructure: native final wait released")
        .unwrap();
    assert!(matches!(result, Err(Error::Unauthorized)));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    observer.close().await;
    f.rebind().await;
    let a = f.begin(json!({}), None).await;
    let captured = delivery::capture(&mut f, &a, None).await;
    f.commit(delivery::finish(&f, &a, captured).await.unwrap())
        .await;
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 2);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 2);
}
