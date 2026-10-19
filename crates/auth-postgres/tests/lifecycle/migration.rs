use crate::support::*;
use auth_core::Repository;
use sqlx::PgPool;

#[sqlx::test(migrations = false)]
async fn lifecycle_migration_requires_reauthentication_for_legacy_sessions(pool: PgPool) {
    for source in [
        include_str!("../../migrations/0001_email_sessions.sql"),
        include_str!("../../migrations/0002_password_credentials.sql"),
        include_str!("../../migrations/0003_password_recovery.sql"),
    ] {
        sqlx::raw_sql(source).execute(&pool).await.unwrap();
    }
    let (store, realm) = realm(pool.clone()).await;
    let fixture = legacy::seed_session(&pool, realm, "alice@example.com").await;
    let legacy = fixture.secret;
    sqlx::raw_sql(include_str!("../../migrations/0004_account_lifecycle.sql"))
        .execute(&pool)
        .await
        .unwrap();
    for source in [
        include_str!("../../migrations/0005_session_management.sql"),
        include_str!("../../migrations/0006_safe_audit.sql"),
        include_str!("../../migrations/0007_passkey_enrollment.sql"),
        include_str!("../../migrations/0008_passkey_authentication.sql"),
        include_str!("../../migrations/0009_optional_mailbox.sql"),
    ] {
        sqlx::raw_sql(source).execute(&pool).await.unwrap();
    }
    assert!(store.authenticate(realm, legacy.verifier()).await.is_ok());
    assert!(
        store
            .begin_account_deletion(realm, legacy.verifier(), [1; 32], [2; 32])
            .await
            .is_err()
    );
    assert!(
        store
            .begin_email_change(
                realm,
                legacy.verifier(),
                "new@example.com",
                [1; 32],
                [2; 32],
                [3; 32]
            )
            .await
            .is_err()
    );
    let fresh = signed_in(&store, realm, "alice@example.com").await;
    assert!(
        store
            .begin_account_deletion(realm, fresh.verifier(), [1; 32], [2; 32])
            .await
            .is_ok()
    );
}
