use super::*;
use crate::support::{legacy, realm};

#[sqlx::test(migrations = false)]
async fn upgrade_preserves_existing_mailbox_session_and_supports_attachment_without_assurance_upgrade(
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
        include_str!("../../../../migrations/0010_passkey_signup.sql"),
    ] {
        sqlx::raw_sql(source).execute(&pool).await.unwrap();
    }
    let before = store
        .authenticate(realm, old.secret.verifier())
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
    let f = Fixture::new(pool.clone()).await;
    let (proof, browser) = f.proof("contact@example.com").await;
    f.store
        .finish_email_attachment(
            f.realm,
            f.current.verifier(),
            proof.verifier(),
            browser.verifier(),
            [8; 32],
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .authenticate(realm, old.secret.verifier())
            .await
            .unwrap(),
        before
    );
    let method: String =
        sqlx::query_scalar("SELECT authentication_method FROM auth_sessions WHERE id=$1")
            .bind(old.session_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(method, "legacy_unknown");
    assert_eq!(f.audits().await, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn revocation_cancels_attachment_and_user_erasure_cascades_pending_state(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let (proof, browser) = f.proof("contact@example.com").await;
    f.store
        .revoke_all_sessions(f.realm, f.current.verifier())
        .await
        .unwrap();
    assert!(
        f.store
            .finish_email_attachment(
                f.realm,
                f.current.verifier(),
                proof.verifier(),
                browser.verifier(),
                [8; 32]
            )
            .await
            .is_err()
    );
    let pending: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_email_attachments WHERE realm_id=$1")
            .bind(f.realm)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(pending, 0);
    let peer = Fixture::new(pool.clone()).await;
    let _ = peer.proof("other@example.com").await;
    // FK erasure behavior only; public stronger-account deletion remains AUTH-20.
    sqlx::query("DELETE FROM auth_users WHERE realm_id=$1 AND id=$2")
        .bind(peer.realm)
        .bind(peer.user)
        .execute(&pool)
        .await
        .unwrap();
    let pending: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_email_attachments WHERE realm_id=$1")
            .bind(peer.realm)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(pending, 0);
}
