use super::{gates::*, *};
use crate::support::reset_proof;
use auth_core::Error;

#[sqlx::test(migrations = "./migrations")]
async fn password_enrollment_cannot_outlive_original_fresh_authentication_during_audit(
    pool: PgPool,
) {
    let f = Fixture::new(pool.clone()).await;
    let deadline = arm_freshness(&pool, f.realm).await;
    let before = f.snapshot().await;
    let gate = write_gate(&pool, "auth_audit", "password_enrolled").await;
    let store = f.store.clone();
    let current = f.session.verifier();
    let finish = tokio::spawn(async move {
        store
            .enroll_password(f.realm, current, "new-hash", [8; 32])
            .await
    });
    wait_and_expire(&pool, "%INSERT%auth_audit%", &deadline, f.realm).await;
    gate.commit().await.unwrap();
    assert!(
        matches!(finished(finish).await, Err(Error::Unauthorized)),
        "stale authentication cannot commit password enrollment"
    );
    f.assert_unchanged(before).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn reset_proof_expiry_during_final_notice_rolls_back_password_sessions_audit_and_proof(
    pool: PgPool,
) {
    let f = Fixture::with_password(pool.clone()).await;
    let (token, browser) = reset_proof(&f.store, f.realm, EMAIL).await;
    let deadline = arm_proof(&pool, "auth_password_resets", f.realm).await;
    let before = f.snapshot().await;
    let gate = write_gate(&pool, "auth_security_notifications", "password_reset").await;
    let store = f.store.clone();
    let finish = tokio::spawn(async move {
        store
            .finish_password_reset(f.realm, token.verifier(), browser.verifier(), "new-hash")
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
        "expired reset proof cannot commit after notification wait"
    );
    f.assert_unchanged(before).await;
}
