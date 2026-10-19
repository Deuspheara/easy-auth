use super::{change_proofs, deletion_proof};
use crate::support::*;
use auth_core::{Error, Repository};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn lifecycle_notice_failure_rolls_back_all_changes(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let current = signed_in(&store, realm, "alice@example.com").await;
    let (old, new, browser) =
        change_proofs(&store, realm, current.verifier(), "new@example.com").await;
    assert!(
        !store
            .confirm_email_change(
                realm,
                current.verifier(),
                old.verifier(),
                browser.verifier()
            )
            .await
            .unwrap()
    );
    sqlx::query("ALTER TABLE auth_security_notifications ADD CONSTRAINT injected_change_failure CHECK (kind<>'email_changed')").execute(&pool).await.unwrap();
    assert!(matches!(
        store
            .confirm_email_change(
                realm,
                current.verifier(),
                new.verifier(),
                browser.verifier()
            )
            .await,
        Err(Error::Unavailable)
    ));
    assert_eq!(
        store
            .authenticate(realm, current.verifier())
            .await
            .unwrap()
            .email
            .as_deref(),
        Some("alice@example.com")
    );
    sqlx::query("ALTER TABLE auth_security_notifications DROP CONSTRAINT injected_change_failure")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        store
            .confirm_email_change(
                realm,
                current.verifier(),
                new.verifier(),
                browser.verifier()
            )
            .await
            .unwrap()
    );
    let current = signed_in(&store, realm, "new@example.com").await;
    let user = store.authenticate(realm, current.verifier()).await.unwrap();
    let (token, browser) = deletion_proof(&store, realm, current.verifier()).await;
    sqlx::query("ALTER TABLE auth_security_notifications ADD CONSTRAINT injected_delete_failure CHECK (kind<>'account_deleted')").execute(&pool).await.unwrap();
    assert!(matches!(
        store
            .finish_account_deletion(
                realm,
                current.verifier(),
                token.verifier(),
                browser.verifier()
            )
            .await,
        Err(Error::Unavailable)
    ));
    assert_eq!(
        store.authenticate(realm, current.verifier()).await.unwrap(),
        user
    );
    let linked: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND user_id=$2")
            .bind(realm)
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(linked > 0);
    sqlx::query("ALTER TABLE auth_security_notifications DROP CONSTRAINT injected_delete_failure")
        .execute(&pool)
        .await
        .unwrap();
    store
        .finish_account_deletion(
            realm,
            current.verifier(),
            token.verifier(),
            browser.verifier(),
        )
        .await
        .unwrap();
}
