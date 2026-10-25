use super::{
    commit_probe::{Action, Probe},
    token_setup::Tokens,
};
use auth_core::{IssuerTokenError, Repository, Secret};
use sqlx::PgPool;
use std::sync::Arc;

#[sqlx::test]
async fn sequential_policy_changes_after_signing_refuse_return_without_consuming_code(
    pool: PgPool,
) {
    for (action, expected) in [
        (Action::DisableIssuer, IssuerTokenError::Unavailable),
        (Action::DisableClient, IssuerTokenError::InvalidClient),
        (Action::RevokeSession, IssuerTokenError::InvalidGrant),
        (Action::ShortenCode, IssuerTokenError::InvalidGrant),
    ] {
        let f = Tokens::new(pool.clone()).await;
        let code = f.code().await;
        let service = f.with_repository(Arc::new(Probe {
            store: f.store.clone(),
            pool: f.pool.clone(),
            action,
        }));
        let result = service
            .exchange(
                &f.authentication(),
                &code,
                "https://app.example/cb",
                &f.pkce,
                "127.0.0.1",
            )
            .await;
        assert!(matches!(
            (&result, &expected),
            (
                Err(IssuerTokenError::Unavailable),
                IssuerTokenError::Unavailable
            ) | (
                Err(IssuerTokenError::InvalidClient),
                IssuerTokenError::InvalidClient
            ) | (
                Err(IssuerTokenError::InvalidGrant),
                IssuerTokenError::InvalidGrant
            )
        ));
        assert_eq!(f.facts().await, (1, 1, 0, 0));
        let preserved:bool=sqlx::query_scalar("SELECT status='approved' AND nonce IS NOT NULL AND consumed_at_us IS NULL FROM auth_issuer_authorizations WHERE realm_id=$1")
            .bind(f.authority.realm()).fetch_one(&f.pool).await.unwrap();
        assert!(preserved);
    }
}

#[sqlx::test]
async fn expiring_signed_output_rolls_back_final_access_code_and_audit_writes(pool: PgPool) {
    let f = Tokens::new(pool).await;
    let code = f.code().await;
    sqlx::query("UPDATE auth_issuer_authorizations SET code_expires_at_us=(extract(epoch FROM clock_timestamp())*1000000)::bigint+4000000 WHERE realm_id=$1")
        .bind(f.authority.realm()).execute(&f.pool).await.unwrap();
    let service = f.with_repository(Arc::new(Probe {
        store: f.store.clone(),
        pool: f.pool.clone(),
        action: Action::WaitUntilExpiring,
    }));
    assert!(matches!(
        service
            .exchange(
                &f.authentication(),
                &code,
                "https://app.example/cb",
                &f.pkce,
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidGrant)
    ));
    assert_eq!(f.facts().await, (1, 1, 0, 0));
    let preserved:bool=sqlx::query_scalar("SELECT status='approved' AND consumed_at_us IS NULL AND nonce IS NOT NULL AND pkce_challenge IS NOT NULL FROM auth_issuer_authorizations WHERE realm_id=$1")
        .bind(f.authority.realm()).fetch_one(&f.pool).await.unwrap();
    assert!(preserved);
}

#[sqlx::test]
async fn confirmed_erasure_cascades_access_codes_and_subjects_but_keeps_other_realm_and_public_keys(
    pool: PgPool,
) {
    let f = Tokens::new(pool.clone()).await;
    let code = f.code().await;
    f.service()
        .exchange(
            &f.authentication(),
            &code,
            "https://app.example/cb",
            &f.pkce,
            "127.0.0.1",
        )
        .await
        .unwrap();
    let other = Tokens::new(pool).await;
    let other_code = other.code().await;
    other
        .service()
        .exchange(
            &other.authentication(),
            &other_code,
            "https://app.example/cb",
            &other.pkce,
            "127.0.0.1",
        )
        .await
        .unwrap();
    let token = Secret::generate().unwrap();
    let browser = Secret::generate().unwrap();
    f.store
        .begin_account_deletion(
            f.authority.realm(),
            f.current.verifier(),
            token.verifier(),
            browser.verifier(),
        )
        .await
        .unwrap();
    f.store
        .finish_account_deletion(
            f.authority.realm(),
            f.current.verifier(),
            token.verifier(),
            browser.verifier(),
        )
        .await
        .unwrap();
    assert_eq!(f.facts().await, (0, 0, 0, 1));
    assert_eq!(other.facts().await, (1, 1, 1, 1));
    assert_eq!(
        f.store
            .issuer_public_keys(&f.authority)
            .await
            .unwrap()
            .len(),
        1
    );
    let removed: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_issuer_authorizations WHERE realm_id=$1")
            .bind(f.authority.realm())
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(removed, 0);
    let deidentified:bool=sqlx::query_scalar("SELECT bool_and(subject_erased AND user_id IS NULL AND actor_session_id IS NULL AND issuer_authorization_id IS NULL AND issuer_client_id IS NULL) FROM auth_audit WHERE realm_id=$1 AND kind IN ('issuer_authorized','issuer_code_redeemed')")
        .bind(f.authority.realm()).fetch_one(&f.pool).await.unwrap();
    assert!(deidentified);
}
