use crate::support::*;
use auth_core::{Error, Repository, Secret};
use sqlx::PgPool;
use uuid::Uuid;

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
        "UPDATE auth_sessions SET authenticated_at=now()-interval '6 minutes' WHERE token_hash=$1",
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
    sqlx::query("UPDATE auth_sessions SET authenticated_at=now() WHERE token_hash=$1")
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
