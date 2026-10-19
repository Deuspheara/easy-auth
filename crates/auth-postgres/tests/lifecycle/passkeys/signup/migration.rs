use super::*;
use crate::support::{legacy, realm};

#[sqlx::test(migrations = false)]
async fn signup_upgrade_preserves_existing_identity_and_provenance_and_supports_new_proof_flow(
    pool: PgPool,
) {
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
    let old = legacy::seed_session(&pool, realm, "existing@example.com").await;
    for source in [
        include_str!("../../../../migrations/0006_safe_audit.sql"),
        include_str!("../../../../migrations/0007_passkey_enrollment.sql"),
        include_str!("../../../../migrations/0008_passkey_authentication.sql"),
        include_str!("../../../../migrations/0009_optional_mailbox.sql"),
    ] {
        sqlx::raw_sql(source).execute(&pool).await.unwrap();
    }
    let before = store
        .authenticate(realm, old.secret.verifier())
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
    let mut f = Signup::new(pool.clone()).await;
    let (id, response) = f.assertion().await;
    assert!(
        f.flow
            .finish(&f.browser, SOURCE, id, &response)
            .await
            .is_ok()
    );
    assert_eq!(
        store
            .authenticate(realm, old.secret.verifier())
            .await
            .unwrap(),
        before
    );
    let method: String = sqlx::query_scalar(
        "SELECT authentication_method FROM auth_sessions WHERE realm_id=$1 AND id=$2",
    )
    .bind(realm)
    .bind(old.session_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(method, "legacy_unknown");
    let kind: String = sqlx::query_scalar("SELECT kind FROM auth_audit WHERE realm_id=$1")
        .bind(f.realm)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(kind, "passkey_signed_up");
}

#[sqlx::test(migrations = "./migrations")]
async fn pending_stage_constraints_reject_partial_or_overlapping_private_state(pool: PgPool) {
    let f = Signup::new(pool).await;
    let pending = f.flow.begin("Person", &f.browser, SOURCE).await.unwrap();
    for statement in [
        "UPDATE auth_passkey_signups SET stage='assertion' WHERE id=$1",
        "UPDATE auth_passkey_signups SET candidate_id=decode('01','hex') WHERE id=$1",
        "UPDATE auth_passkey_signups SET registration_state=decode('','hex') WHERE id=$1",
    ] {
        let error = sqlx::query(statement)
            .bind(pending.transaction)
            .execute(&f.pool)
            .await
            .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("23514")
        );
    }
    assert_eq!(f.durable_counts().await, (0, 0, 0, 0));
}
