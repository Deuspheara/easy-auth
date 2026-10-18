use auth_core::{Error, Repository, Secret};
use easy_auth_postgres::Postgres;
use sqlx::PgPool;
use uuid::Uuid;

async fn realm(pool: PgPool) -> (Postgres, Uuid) {
    let store = Postgres::new(pool);
    let realm = Uuid::new_v4();
    store.ensure_realm(realm).await.unwrap();
    (store, realm)
}
async fn challenge(store: &Postgres, realm: Uuid, email: &str) -> (Secret, Secret) {
    let token = Secret::generate().unwrap();
    let browser = Secret::generate().unwrap();
    store
        .begin_email(realm, email, token.verifier(), browser.verifier(), [1; 32])
        .await
        .unwrap();
    (token, browser)
}
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
async fn expiry_and_idle_limits_cannot_be_revived(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let (token, browser) = challenge(&store, realm, "alice@example.com").await;
    sqlx::query("UPDATE auth_email_challenges SET expires_at=now()-interval '1 second'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        store
            .finish_email(realm, token.verifier(), browser.verifier(), [7; 32])
            .await
            .is_err()
    );
    for update in [
        "UPDATE auth_sessions SET last_seen_at=now()-interval '31 minutes'",
        "UPDATE auth_sessions SET expires_at=now()-interval '1 second'",
    ] {
        let (token, browser) = challenge(&store, realm, "alice@example.com").await;
        let session = Secret::generate().unwrap();
        store
            .finish_email(
                realm,
                token.verifier(),
                browser.verifier(),
                session.verifier(),
            )
            .await
            .unwrap();
        sqlx::query(update).execute(&pool).await.unwrap();
        assert!(store.authenticate(realm, session.verifier()).await.is_err());
    }
}
#[sqlx::test(migrations = "./migrations")]
async fn admission_is_atomic_and_multi_dimensional(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
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
}
#[sqlx::test(migrations = "./migrations")]
async fn composite_foreign_keys_reject_cross_tenant_users(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let (token, browser) = challenge(&store, realm, "alice@example.com").await;
    let user = store
        .finish_email(realm, token.verifier(), browser.verifier(), [2; 32])
        .await
        .unwrap();
    let other = Uuid::new_v4();
    store.ensure_realm(other).await.unwrap();
    let result = sqlx::query(
        "INSERT INTO auth_sessions(realm_id,id,user_id,token_hash) VALUES ($1,$2,$3,$4)",
    )
    .bind(other)
    .bind(Uuid::new_v4())
    .bind(user.id)
    .bind([0u8; 32].as_slice())
    .execute(&pool)
    .await;
    assert!(result.is_err());
}
