use super::*;
use auth_core::{AuthenticationPolicy, Error};

#[sqlx::test(migrations = "./migrations")]
async fn attachment_preserves_identity_policy_and_actual_authentication_time_and_revokes_old_sessions(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '2 minutes' WHERE id=$1")
        .bind(f.actor).execute(&f.pool).await.unwrap();
    let (proof, browser) = f.proof("contact@example.com").await;
    let replacement = Secret::generate().unwrap();
    f.store
        .finish_email_attachment(
            f.realm,
            f.current.verifier(),
            proof.verifier(),
            browser.verifier(),
            replacement.verifier(),
        )
        .await
        .unwrap();
    let user = f
        .store
        .authenticate(f.realm, replacement.verifier())
        .await
        .unwrap();
    assert_eq!(user.id, f.user);
    assert_eq!(user.email.as_deref(), Some("contact@example.com"));
    assert_eq!(
        user.authentication_policy,
        AuthenticationPolicy::PasskeyRequired
    );
    assert!(
        f.store
            .authenticate(f.realm, f.current.verifier())
            .await
            .is_err()
    );
    let preserved: (bool,bool,bool) = sqlx::query_as("SELECT n.authenticated_at=o.authenticated_at,n.authentication_method=o.authentication_method,o.revoked_at IS NOT NULL FROM auth_sessions n JOIN auth_sessions o ON o.realm_id=n.realm_id AND o.user_id=n.user_id WHERE o.id=$1 AND n.token_hash=$2")
        .bind(f.actor).bind(replacement.verifier().as_slice()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(preserved, (true, true, true));
    assert_eq!(f.audits().await, 1);
    assert!(matches!(
        f.store
            .finish_email_attachment(
                f.realm,
                replacement.verifier(),
                proof.verifier(),
                browser.verifier(),
                [9; 32]
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.audits().await, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn insertion_or_audit_failure_rolls_back_mailbox_rotation_and_proof_consumption(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let (proof, browser) = f.proof("contact@example.com").await;
    for (table, condition) in [
        ("auth_sessions", "revoked_at IS NOT NULL"),
        ("auth_audit", "kind<>'email_attached'"),
    ] {
        // Existing live session makes the first CHECK invalid for old rows; NOT
        // VALID still enforces every new/updated tuple during the attempted rotation.
        sqlx::query(&format!("ALTER TABLE {table} ADD CONSTRAINT injected_attachment_failure CHECK ({condition}) NOT VALID"))
            .execute(&f.pool).await.unwrap();
        assert!(matches!(
            f.store
                .finish_email_attachment(
                    f.realm,
                    f.current.verifier(),
                    proof.verifier(),
                    browser.verifier(),
                    [7; 32]
                )
                .await,
            Err(Error::Unavailable)
        ));
        assert_eq!(f.email().await, None);
        assert_eq!(f.audits().await, 0);
        sqlx::query(&format!(
            "ALTER TABLE {table} DROP CONSTRAINT injected_attachment_failure"
        ))
        .execute(&f.pool)
        .await
        .unwrap();
        assert!(
            f.store
                .authenticate(f.realm, f.current.verifier())
                .await
                .is_ok()
        );
    }
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
            .is_ok()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn preissued_mailbox_proofs_are_canceled_and_new_mailbox_authentication_stays_forbidden(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let (mail, binding) = crate::support::challenge(&f.store, f.realm, "contact@example.com").await;
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
    assert!(matches!(
        f.store
            .finish_email(f.realm, mail.verifier(), binding.verifier(), [9; 32])
            .await,
        Err(Error::Unauthorized)
    ));
    let (mail, binding) = crate::support::challenge(&f.store, f.realm, "contact@example.com").await;
    assert!(matches!(
        f.store
            .finish_email(f.realm, mail.verifier(), binding.verifier(), [9; 32])
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.store
            .enroll_password(f.realm, [8; 32], "hash", [9; 32])
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.audits().await, 1);
}
