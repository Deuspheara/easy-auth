use super::Fixture;
use crate::support::{challenge, reset_proof, signed_in};
use auth_core::{Error, Repository};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn stronger_account_denies_mailbox_lifecycle_password_and_email_session_issuance(
    pool: PgPool,
) {
    for email in [None, Some("alice@example.com")] {
        let f = Fixture::new(pool.clone(), email).await;
        let (current, _) = f.session("passkey").await;
        assert!(matches!(
            f.store
                .enroll_password(f.realm, current.verifier(), "new-hash", [1; 32])
                .await,
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            f.store
                .begin_email_change(
                    f.realm,
                    current.verifier(),
                    "new@example.com",
                    [2; 32],
                    [3; 32],
                    [4; 32]
                )
                .await,
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            f.store
                .begin_account_deletion(f.realm, current.verifier(), [5; 32], [6; 32])
                .await,
            Err(Error::Unauthorized)
        ));
        if let Some(email) = email {
            sqlx::query("INSERT INTO auth_password_credentials(realm_id,user_id,password_hash) VALUES ($1,$2,'old-hash')")
                .bind(f.realm).bind(f.user).execute(&pool).await.unwrap();
            assert_eq!(f.store.password_hash(f.realm, email).await.unwrap(), None);
            assert!(matches!(
                f.store
                    .password_login(f.realm, email, "old-hash", [7; 32])
                    .await,
                Err(Error::Unauthorized)
            ));
            let (proof, browser) = challenge(&f.store, f.realm, email).await;
            assert!(matches!(
                f.store
                    .finish_email(f.realm, proof.verifier(), browser.verifier(), [8; 32])
                    .await,
                Err(Error::Unauthorized)
            ));
            let pending: i64 =
                sqlx::query_scalar("SELECT count(*) FROM auth_email_challenges WHERE realm_id=$1")
                    .bind(f.realm)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(
                pending, 1,
                "failed issuance must roll back challenge consumption"
            );
            let (reset, browser) = reset_proof(&f.store, f.realm, email).await;
            assert!(matches!(
                f.store
                    .password_reset_email(f.realm, reset.verifier(), browser.verifier())
                    .await,
                Err(Error::Unauthorized)
            ));
            assert!(matches!(
                f.store
                    .finish_password_reset(
                        f.realm,
                        reset.verifier(),
                        browser.verifier(),
                        "new-hash"
                    )
                    .await,
                Err(Error::Unauthorized)
            ));
        }
        let sessions: i64 =
            sqlx::query_scalar("SELECT count(*) FROM auth_sessions WHERE realm_id=$1")
                .bind(f.realm)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(sessions, 1);
        assert!(
            f.store
                .claim_security_notice(f.realm)
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn preissued_reset_and_lifecycle_proofs_cannot_bypass_changed_policy(pool: PgPool) {
    let (store, realm) = crate::support::realm(pool.clone()).await;
    let current = signed_in(&store, realm, "alice@example.com").await;
    let user = store.authenticate(realm, current.verifier()).await.unwrap();
    sqlx::query("INSERT INTO auth_password_credentials(realm_id,user_id,password_hash) VALUES ($1,$2,'old-hash')")
        .bind(realm).bind(user.id).execute(&pool).await.unwrap();
    let (reset, browser) = reset_proof(&store, realm, "alice@example.com").await;
    store
        .begin_account_deletion(realm, current.verifier(), [1; 32], [2; 32])
        .await
        .unwrap();
    store
        .begin_email_change(
            realm,
            current.verifier(),
            "new@example.com",
            [3; 32],
            [4; 32],
            [5; 32],
        )
        .await
        .unwrap();
    sqlx::query("UPDATE auth_users SET authentication_policy='passkey_required' WHERE realm_id=$1 AND id=$2")
        .bind(realm).bind(user.id).execute(&pool).await.unwrap();
    // A passkey-method fixture permits testing the operation's own policy gate.
    sqlx::query("UPDATE auth_sessions SET authentication_method='passkey' WHERE token_hash=$1")
        .bind(current.verifier().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        store
            .finish_password_reset(realm, reset.verifier(), browser.verifier(), "new-hash")
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        store
            .finish_account_deletion(realm, current.verifier(), [1; 32], [2; 32])
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        store
            .confirm_email_change(realm, current.verifier(), [3; 32], [5; 32])
            .await,
        Err(Error::Unauthorized)
    ));
    let unchanged: String = sqlx::query_scalar(
        "SELECT password_hash FROM auth_password_credentials WHERE realm_id=$1 AND user_id=$2",
    )
    .bind(realm)
    .bind(user.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(unchanged, "old-hash");
    assert!(store.authenticate(realm, current.verifier()).await.is_ok());
}
