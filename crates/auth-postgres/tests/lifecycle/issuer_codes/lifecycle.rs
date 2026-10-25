use super::*;
use auth_core::{Error, IssuerTokenError};

#[sqlx::test]
async fn consent_creates_no_local_authority_and_redeems_once_with_original_facts(pool: PgPool) {
    let f = Fixture::new(&pool, false).await;
    let users = f.count(&pool, "auth_users").await;
    let sessions = f.count(&pool, "auth_sessions").await;
    let pending = f.prepare().await.unwrap();
    assert_eq!(f.count(&pool, "auth_issuer_subjects").await, 0);
    let pending_shape: bool = sqlx::query_scalar("SELECT status='pending' AND code_hash IS NULL AND subject IS NULL FROM auth_issuer_authorizations WHERE realm_id=$1")
        .bind(f.realm).fetch_one(&pool).await.unwrap();
    assert!(pending_shape);
    let code = f.approve(&pending).await;
    assert!(matches!(
        f.service
            .approve(
                &f.current,
                &f.browser,
                pending.handle(),
                pending.authorization()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    let grant = f
        .service
        .redeem(
            &f.authentication(),
            &code,
            &f.redirect,
            &f.pkce,
            "127.0.0.1",
        )
        .await
        .unwrap();
    assert_eq!(grant.owner(), f.owner);
    assert_ne!(grant.subject(), f.owner);
    assert_eq!(grant.nonce(), "client-nonce");
    assert_eq!(grant.authentication_method(), "email");
    assert_eq!(grant.authorization(), pending.authorization());
    assert!(grant.authenticated_at_us() <= grant.issued_at_us());
    assert!(grant.issued_at_us() < grant.expires_at_us());
    assert!(grant.expires_at_us() <= pending.expires_at_us());
    assert!(grant.expires_at_us() - grant.issued_at_us() <= 60_000_000);
    let scrubbed: bool = sqlx::query_scalar("SELECT status='consumed' AND state IS NULL AND nonce IS NULL AND pkce_challenge IS NULL AND code_hash=$2 FROM auth_issuer_authorizations WHERE realm_id=$1")
        .bind(f.realm).bind(code.verifier().as_slice()).fetch_one(&pool).await.unwrap();
    assert!(scrubbed);
    assert_eq!(f.count(&pool, "auth_users").await, users);
    assert_eq!(f.count(&pool, "auth_sessions").await, sessions);
    let events: Vec<String> = sqlx::query_scalar(
        "SELECT kind FROM auth_audit WHERE realm_id=$1 AND issuer_authorization_id=$2 ORDER BY id",
    )
    .bind(f.realm)
    .bind(pending.authorization())
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(events, ["issuer_authorized", "issuer_code_redeemed"]);
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
        Err(IssuerTokenError::InvalidGrant)
    ));
}

#[sqlx::test]
async fn cancellation_is_bound_one_use_denial_without_subject_or_code(pool: PgPool) {
    let f = Fixture::new(&pool, false).await;
    let pending = f.prepare().await.unwrap();
    let denied = f
        .service
        .cancel(
            &f.current,
            &f.browser,
            pending.handle(),
            pending.authorization(),
        )
        .await
        .unwrap();
    let uri = url::Url::parse(denied.url()).unwrap();
    assert!(
        uri.query_pairs()
            .any(|(k, v)| k == "error" && v == "access_denied")
    );
    assert!(!uri.query_pairs().any(|(k, _)| k == "code"));
    assert_eq!(f.count(&pool, "auth_issuer_authorizations").await, 0);
    assert_eq!(f.count(&pool, "auth_issuer_subjects").await, 0);
    assert!(
        f.service
            .cancel(
                &f.current,
                &f.browser,
                pending.handle(),
                pending.authorization()
            )
            .await
            .is_err()
    );
    assert!(
        f.store
            .authenticate(f.realm, f.current.verifier())
            .await
            .is_ok()
    );
}
