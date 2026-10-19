use super::*;
use auth_core::Error;

#[sqlx::test(migrations = "./migrations")]
async fn proof_is_bound_to_realm_owner_initiating_session_and_browser(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (proof, browser) = f.proof("contact@example.com").await;
    let other = crate::support::signed_in(&f.store, f.realm, "other@example.com").await;
    let other_realm = Uuid::new_v4();
    f.store.ensure_realm(other_realm).await.unwrap();
    for (realm, current, token, binding) in [
        (
            other_realm,
            f.current.verifier(),
            proof.verifier(),
            browser.verifier(),
        ),
        (
            f.realm,
            other.verifier(),
            proof.verifier(),
            browser.verifier(),
        ),
        (f.realm, f.current.verifier(), [1; 32], browser.verifier()),
        (f.realm, f.current.verifier(), proof.verifier(), [2; 32]),
    ] {
        assert!(matches!(
            f.store
                .finish_email_attachment(realm, current, token, binding, [9; 32])
                .await,
            Err(Error::Unauthorized)
        ));
    }
    // Another genuine-method session of the SAME user cannot redeem this proof.
    sqlx::query("INSERT INTO auth_sessions(realm_id,id,user_id,token_hash,authentication_method) VALUES ($1,$2,$3,$4,'passkey')")
        .bind(f.realm).bind(Uuid::new_v4()).bind(f.user).bind([3u8;32].as_slice()).execute(&f.pool).await.unwrap();
    assert!(matches!(
        f.store
            .finish_email_attachment(
                f.realm,
                [3; 32],
                proof.verifier(),
                browser.verifier(),
                [9; 32]
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.email().await, None);
    assert!(
        f.store
            .finish_email_attachment(
                f.realm,
                f.current.verifier(),
                proof.verifier(),
                browser.verifier(),
                [9; 32]
            )
            .await
            .is_ok()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn weak_unknown_stale_expired_or_revoked_authentication_cannot_authorize_attachment(
    pool: PgPool,
) {
    for update in [
        "authentication_method='email'",
        "authentication_method='password'",
        "authentication_method='legacy_unknown'",
        "authenticated_at=clock_timestamp()-interval '6 minutes'",
        "authenticated_at=clock_timestamp()+interval '1 minute'",
        "expires_at=clock_timestamp()-interval '1 second'",
        "last_seen_at=clock_timestamp()-interval '31 minutes'",
        "revoked_at=clock_timestamp()",
    ] {
        let f = Fixture::new(pool.clone()).await;
        let (proof, browser) = f.proof("contact@example.com").await;
        sqlx::query(&format!("UPDATE auth_sessions SET {update} WHERE id=$1"))
            .bind(f.actor)
            .execute(&pool)
            .await
            .unwrap();
        assert!(matches!(
            f.store
                .begin_email_attachment(
                    f.realm,
                    f.current.verifier(),
                    "another@example.com",
                    [1; 32],
                    [2; 32]
                )
                .await,
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            f.store
                .finish_email_attachment(
                    f.realm,
                    f.current.verifier(),
                    proof.verifier(),
                    browser.verifier(),
                    [9; 32]
                )
                .await,
            Err(Error::Unauthorized)
        ));
        assert_eq!(f.email().await, None);
        assert_eq!(f.audits().await, 0);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn new_request_replaces_old_proof_and_target_mail_budget_is_shared_and_bounded(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (old, browser) = f.proof("old@example.com").await;
    let (new, new_browser) = f.proof("contact@example.com").await;
    assert!(matches!(
        f.store
            .finish_email_attachment(
                f.realm,
                f.current.verifier(),
                old.verifier(),
                browser.verifier(),
                [9; 32]
            )
            .await,
        Err(Error::Unauthorized)
    ));
    for _ in 0..4 {
        let _ = f.proof("contact@example.com").await;
    }
    assert!(matches!(
        f.store
            .begin_email_attachment(
                f.realm,
                f.current.verifier(),
                "contact@example.com",
                [1; 32],
                [2; 32]
            )
            .await,
        Err(Error::RateLimited)
    ));
    assert!(matches!(
        f.store
            .finish_email_attachment(
                f.realm,
                f.current.verifier(),
                new.verifier(),
                new_browser.verifier(),
                [9; 32]
            )
            .await,
        Err(Error::Unauthorized)
    ));
    let pending: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_email_attachments WHERE realm_id=$1")
            .bind(f.realm)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(pending, 1);
}
