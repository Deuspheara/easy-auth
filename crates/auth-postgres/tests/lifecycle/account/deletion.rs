use super::{change_proofs, deletion_proof};
use crate::support::*;
use auth_core::Repository;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn account_deletion_cleans_only_owned_realm_and_removes_audit_subject(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let original = signed_in(&store, realm, "alice@example.com").await;
    store
        .enroll_password(realm, original.verifier(), "old-hash", [1; 32])
        .await
        .unwrap();
    let (reset, reset_browser) = reset_proof(&store, realm, "alice@example.com").await;
    store
        .finish_password_reset(
            realm,
            reset.verifier(),
            reset_browser.verifier(),
            "new-hash",
        )
        .await
        .unwrap();
    let current = signed_in(&store, realm, "alice@example.com").await;
    let user = store.authenticate(realm, current.verifier()).await.unwrap();
    let other = Uuid::new_v4();
    store.ensure_realm(other).await.unwrap();
    let foreign = signed_in(&store, other, "alice@example.com").await;
    let foreign_user = store.authenticate(other, foreign.verifier()).await.unwrap();
    let (pending, bind) = challenge(&store, realm, "alice@example.com").await;
    reset_proof(&store, realm, "alice@example.com").await;
    change_proofs(&store, realm, current.verifier(), "new@example.com").await;
    let (token, browser) = deletion_proof(&store, realm, current.verifier()).await;
    assert!(
        store
            .finish_account_deletion(
                other,
                current.verifier(),
                token.verifier(),
                browser.verifier()
            )
            .await
            .is_err()
    );
    assert!(
        store
            .finish_account_deletion(realm, current.verifier(), token.verifier(), [0; 32])
            .await
            .is_err()
    );
    store
        .finish_account_deletion(
            realm,
            current.verifier(),
            token.verifier(),
            browser.verifier(),
        )
        .await
        .unwrap();
    assert!(store.authenticate(realm, current.verifier()).await.is_err());
    assert!(
        store
            .finish_email(realm, pending.verifier(), bind.verifier(), [9; 32])
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
    assert_eq!(
        store.authenticate(other, foreign.verifier()).await.unwrap(),
        foreign_user
    );
    for table in [
        "auth_sessions",
        "auth_password_credentials",
        "auth_email_changes",
        "auth_account_deletions",
    ] {
        let count: i64 = sqlx::query_scalar(&format!(
            "SELECT count(*) FROM {table} WHERE realm_id=$1 AND user_id=$2"
        ))
        .bind(realm)
        .bind(user.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 0, "{table}");
    }
    let linked: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND user_id=$2")
            .bind(realm)
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(linked, 0);
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_security_notifications WHERE realm_id=$1")
            .bind(realm)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 1);
    let notice = store.claim_security_notice(realm).await.unwrap().unwrap();
    assert!(matches!(
        notice.kind,
        auth_core::SecurityNoticeKind::AccountDeleted
    ));
    assert_eq!(notice.recipient, "alice@example.com");
}
