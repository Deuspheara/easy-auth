use crate::support::{legacy, realm};
use auth_core::Repository;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = false)]
async fn audit_upgrade_keeps_unknown_provenance_and_erases_invalid_legacy_subjects(pool: PgPool) {
    for source in [
        include_str!("../../../migrations/0001_email_sessions.sql"),
        include_str!("../../../migrations/0002_password_credentials.sql"),
        include_str!("../../../migrations/0003_password_recovery.sql"),
        include_str!("../../../migrations/0004_account_lifecycle.sql"),
        include_str!("../../../migrations/0005_session_management.sql"),
    ] {
        sqlx::raw_sql(source).execute(&pool).await.unwrap();
    }
    let (store, realm) = realm(pool.clone()).await;
    let old = legacy::seed_session(&pool, realm, "alice@example.com").await;
    let foreign_realm = Uuid::new_v4();
    store.ensure_realm(foreign_realm).await.unwrap();
    let foreign = legacy::seed_session(&pool, foreign_realm, "alice@example.com").await;
    // The old schema allowed IDs owned only by another realm and completely dangling IDs.
    for subject in [foreign.user_id, Uuid::new_v4()] {
        sqlx::query(
            "INSERT INTO auth_audit(realm_id,user_id,kind) VALUES ($1,$2,'password_reset')",
        )
        .bind(realm)
        .bind(subject)
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::query("INSERT INTO auth_audit(realm_id,user_id,kind) VALUES ($1,$2,'account_deleted')")
        .bind(realm)
        .bind(old.user_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::raw_sql(include_str!("../../../migrations/0006_safe_audit.sql"))
        .execute(&pool)
        .await
        .unwrap();
    let legacy:(i16,Option<Uuid>,Option<Uuid>,bool)=sqlx::query_as("SELECT schema_version,actor_session_id,session_id,subject_erased FROM auth_audit WHERE realm_id=$1 AND kind='email_authenticated'")
        .bind(realm).fetch_one(&pool).await.unwrap();
    assert_eq!(legacy, (0, None, None, false));
    let erased:i64=sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND user_id IS NULL AND subject_erased AND schema_version=0")
        .bind(realm).fetch_one(&pool).await.unwrap();
    assert_eq!(erased, 3);
    assert!(
        store
            .authenticate(realm, old.secret.verifier())
            .await
            .is_ok()
    );
    assert!(
        store
            .authenticate(foreign_realm, foreign.secret.verifier())
            .await
            .is_ok()
    );
    let id: Uuid = sqlx::query_scalar("SELECT id FROM auth_sessions WHERE realm_id=$1 AND id=$2")
        .bind(realm)
        .bind(old.session_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(id, old.session_id);
    let foreign_owner: Uuid =
        sqlx::query_scalar("SELECT user_id FROM auth_audit WHERE realm_id=$1")
            .bind(foreign_realm)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(foreign_owner, foreign.user_id);
}
