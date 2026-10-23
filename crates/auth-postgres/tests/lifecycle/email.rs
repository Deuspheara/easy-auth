use crate::support::*;
use auth_core::{Error, Repository, Secret};
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn proof_is_bound_single_use_and_tenant_isolated(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let other = Uuid::new_v4();
    store.ensure_realm(other).await.unwrap();
    let (token, browser) = challenge(&store, realm, "alice@example.com").await;
    let session = Secret::generate().unwrap();
    assert!(matches!(
        store
            .finish_email(
                other,
                token.verifier(),
                browser.verifier(),
                session.verifier()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        store
            .finish_email(realm, token.verifier(), [3; 32], session.verifier())
            .await,
        Err(Error::Unauthorized)
    ));
    let user = store
        .finish_email(
            realm,
            token.verifier(),
            browser.verifier(),
            session.verifier(),
        )
        .await
        .unwrap();
    assert_eq!(
        store.authenticate(realm, session.verifier()).await.unwrap(),
        user
    );
    assert!(store.authenticate(other, session.verifier()).await.is_err());
    assert!(
        store
            .finish_email(
                realm,
                token.verifier(),
                browser.verifier(),
                session.verifier()
            )
            .await
            .is_err()
    );
    store.revoke(other, session.verifier()).await.unwrap();
    assert!(store.authenticate(realm, session.verifier()).await.is_ok());
    store.revoke(realm, session.verifier()).await.unwrap();
    store.revoke(realm, session.verifier()).await.unwrap();
    assert!(store.authenticate(realm, session.verifier()).await.is_err());
    let audit_count: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_audit")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(audit_count, 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_consumption_has_one_winner(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let (token, browser) = challenge(&store, realm, "alice@example.com").await;
    let a = Secret::generate().unwrap();
    let b = Secret::generate().unwrap();
    let (first, second) = tokio::join!(
        store.finish_email(realm, token.verifier(), browser.verifier(), a.verifier()),
        store.finish_email(realm, token.verifier(), browser.verifier(), b.verifier())
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_sessions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn session_insert_failure_rolls_back_proof_and_identity(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let (first, browser) = challenge(&store, realm, "alice@example.com").await;
    let session = Secret::generate().unwrap();
    store
        .finish_email(
            realm,
            first.verifier(),
            browser.verifier(),
            session.verifier(),
        )
        .await
        .unwrap();
    let (second, browser) = challenge(&store, realm, "bob@example.com").await;
    assert!(matches!(
        store
            .finish_email(
                realm,
                second.verifier(),
                browser.verifier(),
                session.verifier()
            )
            .await,
        Err(Error::Unavailable)
    ));
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_users WHERE email='bob@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
    store
        .finish_email(
            realm,
            second.verifier(),
            browser.verifier(),
            Secret::generate().unwrap().verifier(),
        )
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn admission_is_atomic_and_multi_dimensional(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let window = start_stable_admission_window(&pool).await;
    let mut tasks = Vec::new();
    for _ in 0..12 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            store
                .begin_email(
                    realm,
                    "alice@example.com",
                    Secret::generate().unwrap().verifier(),
                    [0; 32],
                    [1; 32],
                )
                .await
        }));
    }
    let mut admitted = 0;
    for task in tasks {
        if task.await.unwrap().is_ok() {
            admitted += 1;
        }
    }
    assert_eq!(admitted, 5);
    for index in 0..15 {
        store
            .begin_email(
                realm,
                &format!("u{index}@example.com"),
                Secret::generate().unwrap().verifier(),
                [0; 32],
                [1; 32],
            )
            .await
            .unwrap();
    }
    assert!(matches!(
        store
            .begin_email(realm, "last@example.com", [2; 32], [0; 32], [1; 32])
            .await,
        Err(Error::RateLimited)
    ));
    store
        .begin_email(realm, "last@example.com", [2; 32], [0; 32], [9; 32])
        .await
        .unwrap();
    let other = Uuid::new_v4();
    store.ensure_realm(other).await.unwrap();
    store
        .begin_email(other, "alice@example.com", [2; 32], [0; 32], [1; 32])
        .await
        .unwrap();
    assert_eq!(
        admission_window(&pool).await.0,
        window,
        "the limit and isolation controls must exercise the same real rate window"
    );
    let buckets: Vec<i64> = sqlx::query_scalar(
        "SELECT DISTINCT window_id FROM auth_rate_buckets WHERE realm_id=$1 ORDER BY window_id",
    )
    .bind(realm)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(buckets, vec![window]);
}

async fn admission_window(pool: &PgPool) -> (i64, i64) {
    // The existing email policy uses fixed ten-minute statement-time buckets.
    // Read one statement timestamp so window and remaining time agree.
    sqlx::query_as(
        "SELECT floor(extract(epoch FROM statement_timestamp())/600)::bigint, \
         ((floor(extract(epoch FROM statement_timestamp())/600)+1)*600000000 \
         -extract(epoch FROM statement_timestamp())*1000000)::bigint",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn start_stable_admission_window(pool: &PgPool) -> i64 {
    const MIN_TEST_REMAINING_US: i64 = 5_000_000;
    let (window, remaining) = admission_window(pool).await;
    if remaining >= MIN_TEST_REMAINING_US {
        return window;
    }
    // Scheduling only: do not alter clocks, counters, production limits or
    // assertions. A run split over two valid windows cannot prove one limit.
    tokio::time::sleep(std::time::Duration::from_micros(remaining as u64 + 50_000)).await;
    let (window, remaining) = admission_window(pool).await;
    assert!(remaining >= MIN_TEST_REMAINING_US);
    window
}
