use crate::support::{challenge, realm, reset_proof, signed_in};
use auth_core::{Repository, Secret};
use sqlx::PgPool;

async fn reject(pool: &PgPool, kind: &str) {
    // Only fixed test literals are passed to this trigger fixture.
    sqlx::raw_sql(&format!("CREATE FUNCTION reject_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='{kind}' THEN RAISE EXCEPTION 'test audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_audit BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION reject_audit();"))
        .execute(pool).await.unwrap();
}
async fn allow(pool: &PgPool) {
    sqlx::raw_sql("DROP TRIGGER reject_audit ON auth_audit; DROP FUNCTION reject_audit();")
        .execute(pool)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn email_audit_failure_rolls_back_proof_identity_and_session(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let (token, browser) = challenge(&store, realm, "alice@example.com").await;
    reject(&pool, "email_authenticated").await;
    assert!(
        store
            .finish_email(realm, token.verifier(), browser.verifier(), [9; 32])
            .await
            .is_err()
    );
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(users, 0);
    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_sessions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(sessions, 0);
    allow(&pool).await;
    assert!(
        store
            .finish_email(realm, token.verifier(), browser.verifier(), [9; 32])
            .await
            .is_ok()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn enrollment_audit_failure_preserves_old_session_and_does_not_install_a_credential(
    pool: PgPool,
) {
    let (store, realm) = realm(pool.clone()).await;
    let current = signed_in(&store, realm, "alice@example.com").await;
    let replacement = Secret::generate().unwrap();
    reject(&pool, "password_enrolled").await;
    assert!(
        store
            .enroll_password(
                realm,
                current.verifier(),
                "test-credential",
                replacement.verifier()
            )
            .await
            .is_err()
    );
    assert!(store.authenticate(realm, current.verifier()).await.is_ok());
    assert!(
        store
            .authenticate(realm, replacement.verifier())
            .await
            .is_err()
    );
    assert!(
        store
            .password_hash(realm, "alice@example.com")
            .await
            .unwrap()
            .is_none()
    );
    allow(&pool).await;
    assert!(
        store
            .enroll_password(
                realm,
                current.verifier(),
                "test-credential",
                replacement.verifier()
            )
            .await
            .is_ok()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn recovery_audit_failure_preserves_password_sessions_proof_and_notice_state(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let current = signed_in(&store, realm, "alice@example.com").await;
    let replacement = Secret::generate().unwrap();
    store
        .enroll_password(
            realm,
            current.verifier(),
            "before-reset",
            replacement.verifier(),
        )
        .await
        .unwrap();
    let (token, browser) = reset_proof(&store, realm, "alice@example.com").await;
    reject(&pool, "password_reset").await;
    assert!(
        store
            .finish_password_reset(realm, token.verifier(), browser.verifier(), "after-reset")
            .await
            .is_err()
    );
    assert!(
        store
            .authenticate(realm, replacement.verifier())
            .await
            .is_ok()
    );
    assert_eq!(
        store
            .password_hash(realm, "alice@example.com")
            .await
            .unwrap()
            .as_deref(),
        Some("before-reset")
    );
    assert!(
        store
            .password_reset_email(realm, token.verifier(), browser.verifier())
            .await
            .is_ok()
    );
    assert!(store.claim_security_notice(realm).await.unwrap().is_none());
    allow(&pool).await;
    assert!(
        store
            .finish_password_reset(realm, token.verifier(), browser.verifier(), "after-reset")
            .await
            .is_ok()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn email_change_audit_failure_leaves_second_proof_retryable_and_first_confirmed(
    pool: PgPool,
) {
    let (store, realm) = realm(pool.clone()).await;
    let current = signed_in(&store, realm, "alice@example.com").await;
    store
        .begin_email_change(
            realm,
            current.verifier(),
            "new@example.com",
            [1; 32],
            [2; 32],
            [3; 32],
        )
        .await
        .unwrap();
    assert!(
        !store
            .confirm_email_change(realm, current.verifier(), [1; 32], [3; 32])
            .await
            .unwrap()
    );
    reject(&pool, "email_changed").await;
    assert!(
        store
            .confirm_email_change(realm, current.verifier(), [2; 32], [3; 32])
            .await
            .is_err()
    );
    assert_eq!(
        store
            .authenticate(realm, current.verifier())
            .await
            .unwrap()
            .email
            .as_deref(),
        Some("alice@example.com")
    );
    assert!(store.claim_security_notice(realm).await.unwrap().is_none());
    allow(&pool).await;
    assert!(
        store
            .confirm_email_change(realm, current.verifier(), [2; 32], [3; 32])
            .await
            .unwrap()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn deletion_audit_failure_restores_subject_actor_target_and_the_live_account(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let current = signed_in(&store, realm, "alice@example.com").await;
    let user = store.authenticate(realm, current.verifier()).await.unwrap();
    let before: Vec<String> = sqlx::query_scalar(
        "SELECT to_jsonb(a)::text FROM auth_audit a WHERE user_id=$1 ORDER BY id",
    )
    .bind(user.id)
    .fetch_all(&pool)
    .await
    .unwrap();
    store
        .begin_account_deletion(realm, current.verifier(), [1; 32], [2; 32])
        .await
        .unwrap();
    reject(&pool, "account_deleted").await;
    assert!(
        store
            .finish_account_deletion(realm, current.verifier(), [1; 32], [2; 32])
            .await
            .is_err()
    );
    assert_eq!(
        store.authenticate(realm, current.verifier()).await.unwrap(),
        user
    );
    let after: Vec<String> = sqlx::query_scalar(
        "SELECT to_jsonb(a)::text FROM auth_audit a WHERE user_id=$1 ORDER BY id",
    )
    .bind(user.id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(before, after);
    assert!(store.claim_security_notice(realm).await.unwrap().is_none());
    allow(&pool).await;
    assert!(
        store
            .finish_account_deletion(realm, current.verifier(), [1; 32], [2; 32])
            .await
            .is_ok()
    );
}
