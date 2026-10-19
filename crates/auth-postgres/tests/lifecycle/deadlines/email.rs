use super::{gates::*, *};
use crate::support::challenge;
use auth_core::Error;

#[sqlx::test(migrations = "./migrations")]
async fn email_proof_expiry_during_final_audit_rolls_back_identity_session_and_consumption(
    pool: PgPool,
) {
    let f = Fixture::new(pool.clone()).await;
    let (token, browser) = challenge(&f.store, f.realm, "new-deadline-user@example.test").await;
    let deadline = arm_proof(&pool, "auth_email_challenges", f.realm).await;
    let before = f.snapshot().await;
    let gate = write_gate(&pool, "auth_audit", "email_authenticated").await;
    let store = f.store.clone();
    let finish = tokio::spawn(async move {
        store
            .finish_email(f.realm, token.verifier(), browser.verifier(), [8; 32])
            .await
    });
    wait_and_expire(&pool, "%INSERT%auth_audit%", &deadline, f.realm).await;
    gate.commit().await.unwrap();
    assert!(
        matches!(finished(finish).await, Err(Error::Unauthorized)),
        "expired mailbox proof cannot commit after audit wait"
    );
    f.assert_unchanged(before).await;
}
