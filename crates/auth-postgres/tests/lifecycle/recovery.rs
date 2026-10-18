use crate::support::*;
use auth_core::{Error, Repository};
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn reset_is_bound_expiring_single_use_and_revokes_every_session(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let session = signed_in(&store, realm, "alice@example.com").await;
    store
        .enroll_password(realm, session.verifier(), "old-hash", [5; 32])
        .await
        .unwrap();
    let session = signed_in(&store, realm, "alice@example.com").await;
    let (signin, signin_browser) = challenge(&store, realm, "alice@example.com").await;
    let (token, browser) = reset_proof(&store, realm, "alice@example.com").await;
    let (sibling, sibling_browser) = reset_proof(&store, realm, "alice@example.com").await;
    let other = Uuid::new_v4();
    store.ensure_realm(other).await.unwrap();
    assert!(
        store
            .finish_password_reset(other, token.verifier(), browser.verifier(), "new-hash")
            .await
            .is_err()
    );
    assert!(
        store
            .finish_password_reset(realm, token.verifier(), [0; 32], "new-hash")
            .await
            .is_err()
    );
    assert!(
        store
            .finish_password_reset(
                realm,
                signin.verifier(),
                signin_browser.verifier(),
                "new-hash"
            )
            .await
            .is_err()
    );
    assert!(
        store
            .finish_email(realm, token.verifier(), browser.verifier(), [9; 32])
            .await
            .is_err()
    );
    let (expired, expired_browser) = reset_proof(&store, realm, "alice@example.com").await;
    sqlx::query("UPDATE auth_password_resets SET expires_at=clock_timestamp()-interval '1 second' WHERE token_hash=$1")
        .bind(expired.verifier().as_slice()).execute(&pool).await.unwrap();
    assert!(
        store
            .finish_password_reset(
                realm,
                expired.verifier(),
                expired_browser.verifier(),
                "new-hash"
            )
            .await
            .is_err()
    );
    store
        .finish_password_reset(realm, token.verifier(), browser.verifier(), "new-hash")
        .await
        .unwrap();
    assert!(store.authenticate(realm, session.verifier()).await.is_err());
    assert!(store.authenticate(realm, [5; 32]).await.is_err());
    assert!(
        store
            .password_login(realm, "alice@example.com", "old-hash", [6; 32])
            .await
            .is_err()
    );
    assert!(
        store
            .finish_password_reset(realm, token.verifier(), browser.verifier(), "overwrite")
            .await
            .is_err()
    );
    assert!(
        store
            .finish_password_reset(
                realm,
                sibling.verifier(),
                sibling_browser.verifier(),
                "overwrite"
            )
            .await
            .is_err()
    );
    assert!(
        store
            .finish_email(realm, signin.verifier(), signin_browser.verifier(), [8; 32])
            .await
            .is_err()
    );
    store
        .password_login(realm, "alice@example.com", "new-hash", [6; 32])
        .await
        .unwrap();
    assert!(store.authenticate(realm, [6; 32]).await.is_ok());
    let notice = store.claim_security_notice(realm).await.unwrap().unwrap();
    assert_eq!(notice.recipient, "alice@example.com");
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE kind='password_reset'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_resets_and_stale_versions_cannot_replace_credentials(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let session = signed_in(&store, realm, "alice@example.com").await;
    // A proof issued before enrollment cannot later enroll/replace a password.
    let (missing, missing_browser) = reset_proof(&store, realm, "alice@example.com").await;
    store
        .enroll_password(realm, session.verifier(), "old-hash", [1; 32])
        .await
        .unwrap();
    assert!(
        store
            .finish_password_reset(
                realm,
                missing.verifier(),
                missing_browser.verifier(),
                "new-hash"
            )
            .await
            .is_err()
    );
    let (a, ba) = reset_proof(&store, realm, "alice@example.com").await;
    let (b, bb) = reset_proof(&store, realm, "alice@example.com").await;
    let (first, second) = tokio::join!(
        store.finish_password_reset(realm, a.verifier(), ba.verifier(), "first-hash"),
        store.finish_password_reset(realm, b.verifier(), bb.verifier(), "second-hash")
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_security_notifications")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let (token, browser) = reset_proof(&store, realm, "alice@example.com").await;
    sqlx::query("UPDATE auth_password_credentials SET version=gen_random_uuid()")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        store
            .password_reset_email(realm, token.verifier(), browser.verifier())
            .await
            .is_err()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn reset_notification_failure_rolls_back_credential_sessions_and_proof(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let session = signed_in(&store, realm, "alice@example.com").await;
    store
        .enroll_password(realm, session.verifier(), "old-hash", [1; 32])
        .await
        .unwrap();
    let (token, browser) = reset_proof(&store, realm, "alice@example.com").await;
    sqlx::query(
        "ALTER TABLE auth_security_notifications ADD CONSTRAINT injected_failure CHECK (false)",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        store
            .finish_password_reset(realm, token.verifier(), browser.verifier(), "new-hash")
            .await,
        Err(Error::Unavailable)
    ));
    assert_eq!(
        store
            .password_hash(realm, "alice@example.com")
            .await
            .unwrap()
            .unwrap(),
        "old-hash"
    );
    assert!(store.authenticate(realm, [1; 32]).await.is_ok());
    assert!(
        store
            .password_reset_email(realm, token.verifier(), browser.verifier())
            .await
            .is_ok()
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE kind='password_reset'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
    sqlx::query("ALTER TABLE auth_security_notifications DROP CONSTRAINT injected_failure")
        .execute(&pool)
        .await
        .unwrap();
    store
        .finish_password_reset(realm, token.verifier(), browser.verifier(), "new-hash")
        .await
        .unwrap();
}
