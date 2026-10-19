use super::{gates::*, *};
use crate::account::{change_proofs, deletion_proof};
use auth_core::Error;

#[sqlx::test(migrations = "./migrations")]
async fn final_email_change_notice_cannot_outlive_proof_or_original_session(pool: PgPool) {
    for proof_deadline in [true, false] {
        let f = Fixture::with_password(pool.clone()).await;
        let (old, new, browser) = change_proofs(
            &f.store,
            f.realm,
            f.session.verifier(),
            "new-deadline-email@example.test",
        )
        .await;
        assert!(
            !f.store
                .confirm_email_change(
                    f.realm,
                    f.session.verifier(),
                    old.verifier(),
                    browser.verifier()
                )
                .await
                .unwrap()
        );
        let deadline = if proof_deadline {
            arm_proof(&pool, "auth_email_changes", f.realm).await
        } else {
            arm_freshness(&pool, f.realm).await
        };
        let before = f.snapshot().await;
        let gate = write_gate(&pool, "auth_security_notifications", "email_changed").await;
        let store = f.store.clone();
        let current = f.session.verifier();
        let finish = tokio::spawn(async move {
            store
                .confirm_email_change(f.realm, current, new.verifier(), browser.verifier())
                .await
        });
        wait_and_expire(
            &pool,
            "%INSERT%auth_security_notifications%",
            &deadline,
            f.realm,
        )
        .await;
        gate.commit().await.unwrap();
        assert!(
            matches!(finished(finish).await, Err(Error::Unauthorized)),
            "expired email-change authority cannot commit"
        );
        f.assert_unchanged(before).await;
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn final_deletion_notice_cannot_outlive_proof_or_original_session(pool: PgPool) {
    for proof_deadline in [true, false] {
        let f = Fixture::with_password(pool.clone()).await;
        let (token, browser) = deletion_proof(&f.store, f.realm, f.session.verifier()).await;
        let deadline = if proof_deadline {
            arm_proof(&pool, "auth_account_deletions", f.realm).await
        } else {
            arm_freshness(&pool, f.realm).await
        };
        let before = f.snapshot().await;
        let gate = write_gate(&pool, "auth_security_notifications", "account_deleted").await;
        let store = f.store.clone();
        let current = f.session.verifier();
        let finish = tokio::spawn(async move {
            store
                .finish_account_deletion(f.realm, current, token.verifier(), browser.verifier())
                .await
        });
        wait_and_expire(
            &pool,
            "%INSERT%auth_security_notifications%",
            &deadline,
            f.realm,
        )
        .await;
        gate.commit().await.unwrap();
        assert!(
            matches!(finished(finish).await, Err(Error::Unauthorized)),
            "expired deletion authority cannot commit after erasing proof rows"
        );
        f.assert_unchanged(before).await;
    }
}
