use crate::support::{legacy, realm, signed_in};
use auth_core::{Repository, Secret};
use sqlx::PgPool;

#[sqlx::test(migrations = false)]
async fn upgrade_preserves_unknown_methods_and_rotations_do_not_upgrade_assurance(pool: PgPool) {
    for source in [
        include_str!("../../../../migrations/0001_email_sessions.sql"),
        include_str!("../../../../migrations/0002_password_credentials.sql"),
        include_str!("../../../../migrations/0003_password_recovery.sql"),
        include_str!("../../../../migrations/0004_account_lifecycle.sql"),
        include_str!("../../../../migrations/0005_session_management.sql"),
    ] {
        sqlx::raw_sql(source).execute(&pool).await.unwrap();
    }
    let (store, realm) = realm(pool.clone()).await;
    let old = legacy::seed_session(&pool, realm, "alice@example.com").await;
    for source in [
        include_str!("../../../../migrations/0006_safe_audit.sql"),
        include_str!("../../../../migrations/0007_passkey_enrollment.sql"),
    ] {
        sqlx::raw_sql(source).execute(&pool).await.unwrap();
    }
    sqlx::raw_sql(include_str!(
        "../../../../migrations/0008_passkey_authentication.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let method: String =
        sqlx::query_scalar("SELECT authentication_method FROM auth_sessions WHERE id=$1")
            .bind(old.session_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(method, "legacy_unknown");
    sqlx::raw_sql(include_str!(
        "../../../../migrations/0009_optional_mailbox.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::raw_sql(include_str!(
        "../../../../migrations/0010_passkey_signup.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::raw_sql(include_str!(
        "../../../../migrations/0011_email_attachment.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::raw_sql(include_str!(
        "../../../../migrations//0012_passkey_management.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        store
            .authenticate(realm, old.secret.verifier())
            .await
            .is_ok()
    );
    let current = signed_in(&store, realm, "alice@example.com").await;
    let replacement = Secret::generate().unwrap();
    store
        .enroll_password(
            realm,
            current.verifier(),
            "verified-test-hash",
            replacement.verifier(),
        )
        .await
        .unwrap();
    let method: String =
        sqlx::query_scalar("SELECT authentication_method FROM auth_sessions WHERE token_hash=$1")
            .bind(replacement.verifier().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(method, "email");
    let password = Secret::generate().unwrap();
    store
        .password_login(
            realm,
            "alice@example.com",
            "verified-test-hash",
            password.verifier(),
        )
        .await
        .unwrap();
    let method: String =
        sqlx::query_scalar("SELECT authentication_method FROM auth_sessions WHERE token_hash=$1")
            .bind(password.verifier().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(method, "password");
}
