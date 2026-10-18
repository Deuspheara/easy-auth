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

async fn signed_in(store: &Postgres, realm: Uuid, email: &str) -> Secret {
    let (token, browser) = challenge(store, realm, email).await;
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
    session
}

#[sqlx::test(migrations = "./migrations")]
async fn password_enrollment_is_fresh_atomic_and_single_use(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let current = signed_in(&store, realm, "alice@example.com").await;
    let sibling = signed_in(&store, realm, "alice@example.com").await;
    let replacement = Secret::generate().unwrap();
    let other = Uuid::new_v4();
    store.ensure_realm(other).await.unwrap();
    assert!(
        store
            .enroll_password(other, current.verifier(), "hash", replacement.verifier())
            .await
            .is_err()
    );
    sqlx::query(
        "UPDATE auth_sessions SET created_at=now()-interval '6 minutes' WHERE token_hash=$1",
    )
    .bind(current.verifier().as_slice())
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        store
            .enroll_password(realm, current.verifier(), "hash", replacement.verifier())
            .await,
        Err(Error::Unauthorized)
    ));
    sqlx::query("UPDATE auth_sessions SET created_at=now() WHERE token_hash=$1")
        .bind(current.verifier().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    // Force session-insert failure: the credential insert, audit and revocations must roll back.
    assert!(matches!(
        store
            .enroll_password(realm, current.verifier(), "hash", sibling.verifier())
            .await,
        Err(Error::Unavailable)
    ));
    assert!(
        store
            .password_hash(realm, "alice@example.com")
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.authenticate(realm, current.verifier()).await.is_ok());
    let second = Secret::generate().unwrap();
    let (a, b) = tokio::join!(
        store.enroll_password(
            realm,
            current.verifier(),
            "winner-a",
            replacement.verifier()
        ),
        store.enroll_password(realm, sibling.verifier(), "winner-b", second.verifier())
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let stored = store
        .password_hash(realm, "alice@example.com")
        .await
        .unwrap()
        .unwrap();
    assert!(stored == "winner-a" || stored == "winner-b");
    assert!(
        store
            .password_hash(other, "alice@example.com")
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.authenticate(realm, current.verifier()).await.is_err());
    assert!(store.authenticate(realm, sibling.verifier()).await.is_err());
    let winner = if a.is_ok() { &replacement } else { &second };
    assert!(store.authenticate(realm, winner.verifier()).await.is_ok());
    assert!(
        store
            .enroll_password(realm, winner.verifier(), "overwrite", [6; 32])
            .await
            .is_err()
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE kind='password_enrolled'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn password_login_rechecks_credential_and_realm(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let current = signed_in(&store, realm, "alice@example.com").await;
    store
        .enroll_password(realm, current.verifier(), "verified-hash", [1; 32])
        .await
        .unwrap();
    let other = Uuid::new_v4();
    store.ensure_realm(other).await.unwrap();
    for (target, email, hash) in [
        (other, "alice@example.com", "verified-hash"),
        (realm, "missing@example.com", "verified-hash"),
        (realm, "alice@example.com", "changed-hash"),
    ] {
        assert!(matches!(
            store.password_login(target, email, hash, [2; 32]).await,
            Err(Error::Unauthorized)
        ));
    }
    store
        .password_login(realm, "alice@example.com", "verified-hash", [2; 32])
        .await
        .unwrap();
    assert!(store.authenticate(realm, [2; 32]).await.is_ok());
    // Hash snapshots verified before a credential change cannot create a session afterwards.
    sqlx::query("UPDATE auth_password_credentials SET password_hash='new-hash'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        store
            .password_login(realm, "alice@example.com", "verified-hash", [3; 32])
            .await
            .is_err()
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE kind='password_authenticated'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn password_admission_is_shared_and_account_independent(pool: PgPool) {
    let (store, realm) = realm(pool).await;
    let mut tasks = Vec::new();
    for _ in 0..20 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            store
                .admit_password(realm, "missing@example.com", [9; 32])
                .await
        }));
    }
    let mut accepted = 0;
    for task in tasks {
        if task.await.unwrap().is_ok() {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 10);
    for i in 0..30 {
        store
            .admit_password(realm, &format!("u{i}@example.com"), [9; 32])
            .await
            .unwrap();
    }
    assert!(matches!(
        store
            .admit_password(realm, "last@example.com", [9; 32])
            .await,
        Err(Error::RateLimited)
    ));
    store
        .admit_password(realm, "last@example.com", [8; 32])
        .await
        .unwrap();
}
