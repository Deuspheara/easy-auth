use super::*;
use auth_core::{Error, IssuerTokenError};

#[sqlx::test]
async fn audit_failure_rolls_back_subject_approval_and_redemption_before_retry(pool: PgPool) {
    let f = Fixture::new(&pool, false).await;
    let pending = f.prepare().await.unwrap();
    sqlx::query("ALTER TABLE auth_audit ADD CONSTRAINT test_issuer_audit_failure CHECK (kind NOT IN ('issuer_authorized','issuer_code_redeemed'))")
        .execute(&pool).await.unwrap();
    assert!(matches!(
        f.service
            .approve(
                &f.current,
                &f.browser,
                pending.handle(),
                pending.authorization()
            )
            .await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.count(&pool, "auth_issuer_subjects").await, 0);
    let pending_shape: bool = sqlx::query_scalar("SELECT status='pending' AND code_hash IS NULL AND subject IS NULL FROM auth_issuer_authorizations WHERE realm_id=$1")
        .bind(f.realm).fetch_one(&pool).await.unwrap();
    assert!(pending_shape);
    sqlx::query("ALTER TABLE auth_audit DROP CONSTRAINT test_issuer_audit_failure")
        .execute(&pool)
        .await
        .unwrap();
    let code = f.approve(&pending).await;
    sqlx::query("ALTER TABLE auth_audit ADD CONSTRAINT test_issuer_audit_failure CHECK (kind<>'issuer_code_redeemed')")
        .execute(&pool).await.unwrap();
    assert!(matches!(
        f.service
            .redeem(
                &f.authentication(),
                &code,
                &f.redirect,
                &f.pkce,
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::Unavailable)
    ));
    let approved: bool = sqlx::query_scalar("SELECT status='approved' AND consumed_at_us IS NULL AND nonce IS NOT NULL AND pkce_challenge IS NOT NULL FROM auth_issuer_authorizations WHERE realm_id=$1")
        .bind(f.realm).fetch_one(&pool).await.unwrap();
    assert!(approved);
    sqlx::query("ALTER TABLE auth_audit DROP CONSTRAINT test_issuer_audit_failure")
        .execute(&pool)
        .await
        .unwrap();
    f.service
        .redeem(
            &f.authentication(),
            &code,
            &f.redirect,
            &f.pkce,
            "127.0.0.1",
        )
        .await
        .unwrap();
}

#[sqlx::test]
async fn actual_erasure_deidentifies_issuer_audit_and_cascades_codes_only_in_own_realm(
    pool: PgPool,
) {
    let f = Fixture::new(&pool, false).await;
    let pending = f.prepare().await.unwrap();
    let code = f.approve(&pending).await;
    f.service
        .redeem(
            &f.authentication(),
            &code,
            &f.redirect,
            &f.pkce,
            "127.0.0.1",
        )
        .await
        .unwrap();
    let other = Fixture::new(&pool, false).await;
    let other_pending = other.prepare().await.unwrap();
    let other_code = other.approve(&other_pending).await;
    let token = Secret::generate().unwrap();
    let browser = Secret::generate().unwrap();
    f.store
        .begin_account_deletion(
            f.realm,
            f.current.verifier(),
            token.verifier(),
            browser.verifier(),
        )
        .await
        .unwrap();
    f.store
        .finish_account_deletion(
            f.realm,
            f.current.verifier(),
            token.verifier(),
            browser.verifier(),
        )
        .await
        .unwrap();
    assert_eq!(f.count(&pool, "auth_issuer_authorizations").await, 0);
    assert_eq!(f.count(&pool, "auth_issuer_subjects").await, 0);
    let erased: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind IN ('issuer_authorized','issuer_code_redeemed') AND subject_erased AND user_id IS NULL AND actor_session_id IS NULL AND issuer_client_id IS NULL AND issuer_authorization_id IS NULL")
        .bind(f.realm).fetch_one(&pool).await.unwrap();
    assert_eq!(erased, 2);
    other
        .service
        .redeem(
            &other.authentication(),
            &other_code,
            &other.redirect,
            &other.pkce,
            "127.0.0.1",
        )
        .await
        .unwrap();
}
