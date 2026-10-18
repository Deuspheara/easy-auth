use super::{change_proofs, deletion_proof};
use crate::support::*;
use auth_core::Repository;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn lifecycle_rejects_expiry_cross_user_and_wrong_purpose(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let a = signed_in(&store, realm, "alice@example.com").await;
    let b = signed_in(&store, realm, "bob@example.com").await;
    let (old, new, browser) = change_proofs(&store, realm, a.verifier(), "new@example.com").await;
    let (deleted, dbrowser) = deletion_proof(&store, realm, a.verifier()).await;
    assert!(
        store
            .confirm_email_change(realm, b.verifier(), old.verifier(), browser.verifier())
            .await
            .is_err()
    );
    assert!(
        store
            .finish_account_deletion(realm, b.verifier(), deleted.verifier(), dbrowser.verifier())
            .await
            .is_err()
    );
    assert!(
        store
            .confirm_email_change(realm, a.verifier(), deleted.verifier(), dbrowser.verifier())
            .await
            .is_err()
    );
    assert!(
        store
            .finish_account_deletion(realm, a.verifier(), old.verifier(), browser.verifier())
            .await
            .is_err()
    );
    sqlx::query("UPDATE auth_email_changes SET expires_at=clock_timestamp()-interval '1 second'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE auth_account_deletions SET expires_at=clock_timestamp()-interval '1 second'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        store
            .confirm_email_change(realm, a.verifier(), new.verifier(), browser.verifier())
            .await
            .is_err()
    );
    assert!(
        store
            .finish_account_deletion(realm, a.verifier(), deleted.verifier(), dbrowser.verifier())
            .await
            .is_err()
    );
    let (new_delete, new_browser) = deletion_proof(&store, realm, a.verifier()).await;
    sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '6 minutes' WHERE token_hash=$1").bind(a.verifier().as_slice()).execute(&pool).await.unwrap();
    assert!(
        store
            .finish_account_deletion(
                realm,
                a.verifier(),
                new_delete.verifier(),
                new_browser.verifier()
            )
            .await
            .is_err()
    );
    assert!(store.authenticate(realm, a.verifier()).await.is_ok());
}
