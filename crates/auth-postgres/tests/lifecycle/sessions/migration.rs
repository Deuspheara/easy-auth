use super::session;
use crate::support::{realm, signed_in};
use auth_core::Repository;
use sqlx::PgPool;

#[sqlx::test(migrations = false)]
async fn session_management_upgrade_preserves_existing_sessions_and_audit(pool: PgPool) {
    for source in [
        include_str!("../../../migrations/0001_email_sessions.sql"),
        include_str!("../../../migrations/0002_password_credentials.sql"),
        include_str!("../../../migrations/0003_password_recovery.sql"),
        include_str!("../../../migrations/0004_account_lifecycle.sql"),
    ] {
        sqlx::raw_sql(source).execute(&pool).await.unwrap();
    }
    let (store, realm) = realm(pool.clone()).await;
    let current = signed_in(&store, realm, "alice@example.com").await;
    let user = store.authenticate(realm, current.verifier()).await.unwrap();
    let (other, _) = session(&pool, realm, user.id).await;
    sqlx::raw_sql(include_str!(
        "../../../migrations/0005_session_management.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        store
            .list_sessions(realm, current.verifier(), None)
            .await
            .unwrap()
            .sessions
            .len(),
        2
    );
    let existing: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE kind='email_authenticated'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(existing, 1);
    store
        .revoke_all_sessions(realm, current.verifier())
        .await
        .unwrap();
    for secret in [&current, &other] {
        assert!(store.authenticate(realm, secret.verifier()).await.is_err());
    }
    let audited: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE kind='all_sessions_revoked'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(audited, 1);
}
