use crate::support::{legacy, realm};
use auth_core::{AuthenticationPolicy, Repository};
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = false)]
async fn optional_mailbox_upgrade_preserves_identity_verification_and_unknown_provenance(
    pool: PgPool,
) {
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
    let verified: String = sqlx::query_scalar(
        "SELECT email_verified_at::text FROM auth_users WHERE realm_id=$1 AND id=$2",
    )
    .bind(realm)
    .bind(old.user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    for source in [
        include_str!("../../../migrations/0006_safe_audit.sql"),
        include_str!("../../../migrations/0007_passkey_enrollment.sql"),
        include_str!("../../../migrations/0008_passkey_authentication.sql"),
        include_str!("../../../migrations/0009_optional_mailbox.sql"),
        include_str!("../../../migrations/0010_passkey_signup.sql"),
        include_str!("../../../migrations/0011_email_attachment.sql"),
        include_str!("../../../migrations//0012_passkey_management.sql"),
    ] {
        sqlx::raw_sql(source).execute(&pool).await.unwrap();
    }
    crate::support::schema::finish_upgrade_after(&pool, 12).await;
    let user = store
        .authenticate(realm, old.secret.verifier())
        .await
        .unwrap();
    assert_eq!(user.id, old.user_id);
    assert_eq!(user.email.as_deref(), Some("alice@example.com"));
    assert_eq!(user.display_name, None);
    assert_eq!(user.authentication_policy, AuthenticationPolicy::Mailbox);
    let preserved: (String, String, Uuid) = sqlx::query_as("SELECT u.email_verified_at::text,s.authentication_method,s.id FROM auth_users u JOIN auth_sessions s ON s.realm_id=u.realm_id AND s.user_id=u.id WHERE u.realm_id=$1 AND u.id=$2")
        .bind(realm).bind(old.user_id).fetch_one(&pool).await.unwrap();
    assert_eq!(
        preserved,
        (verified, "legacy_unknown".to_owned(), old.session_id)
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn mailbox_constraints_allow_distinct_email_free_users_but_reject_invented_authority(
    pool: PgPool,
) {
    let (_, realm) = realm(pool.clone()).await;
    for _ in 0..2 {
        sqlx::query("INSERT INTO auth_users(realm_id,id,email,email_verified_at,display_name,authentication_policy) VALUES ($1,$2,NULL,NULL,'Same label','passkey_required')")
            .bind(realm).bind(Uuid::new_v4()).execute(&pool).await.unwrap();
    }
    for (email, verified, name, policy) in [
        (None, false, Some("Person"), "mailbox"),
        (None, true, Some("Person"), "passkey_required"),
        (Some("alice@example.com"), false, Some("Person"), "mailbox"),
        (None, false, None, "passkey_required"),
        (None, false, Some(""), "passkey_required"),
        (None, false, Some("  "), "passkey_required"),
        (None, false, Some("Bad\nlabel"), "passkey_required"),
        (None, false, Some("Person"), "unknown"),
    ] {
        let error = sqlx::query("INSERT INTO auth_users(realm_id,id,email,email_verified_at,display_name,authentication_policy) VALUES ($1,$2,$3,CASE WHEN $4 THEN clock_timestamp() ELSE NULL END,$5,$6)")
            .bind(realm).bind(Uuid::new_v4()).bind(email).bind(verified).bind(name).bind(policy)
            .execute(&pool).await.unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("23514")
        );
    }
    sqlx::query("INSERT INTO auth_users(realm_id,id,email) VALUES ($1,$2,'alice@example.com')")
        .bind(realm)
        .bind(Uuid::new_v4())
        .execute(&pool)
        .await
        .unwrap();
    let error =
        sqlx::query("INSERT INTO auth_users(realm_id,id,email) VALUES ($1,$2,'alice@example.com')")
            .bind(realm)
            .bind(Uuid::new_v4())
            .execute(&pool)
            .await
            .unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23505")
    );
    let nulls: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_users WHERE realm_id=$1 AND email IS NULL AND email_verified_at IS NULL")
        .bind(realm).fetch_one(&pool).await.unwrap();
    assert_eq!(nulls, 2);
}
