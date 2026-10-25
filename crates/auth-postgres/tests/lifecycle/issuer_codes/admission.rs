use super::*;
use auth_core::{Error, IssuerAuthorizationRepository, IssuerTokenError};

#[sqlx::test]
async fn failed_redemption_still_spends_budget_and_next_window_is_independent(pool: PgPool) {
    let f = Fixture::new(&pool, false).await;
    let code = Secret::generate().unwrap();
    // One genuine attempt establishes the trusted source digest/window. Seed the
    // penultimate count directly; this is a bounded database policy test.
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
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("UPDATE auth_issuer_token_admission SET attempts=$2-1 WHERE realm_id=$1")
        .bind(f.realm)
        .bind(auth_core::ISSUER_TOKEN_ATTEMPTS_PER_MINUTE)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    // Pass an unknown client: admission occurs before even the client lookup.
    let unknown = IssuerClientAuthentication::public(Uuid::new_v4()).unwrap();
    assert!(matches!(
        f.service
            .redeem(&unknown, &code, &f.redirect, &f.pkce, "127.0.0.1")
            .await,
        Err(IssuerTokenError::InvalidClient)
    ));
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
        Err(IssuerTokenError::RateLimited)
    ));
    sqlx::query("UPDATE auth_issuer_token_admission SET window_id=window_id-1 WHERE realm_id=$1")
        .bind(f.realm)
        .execute(&pool)
        .await
        .unwrap();
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
    let (rows, attempts): (i64, i64) = sqlx::query_as(
        "SELECT count(*),sum(attempts)::bigint FROM auth_issuer_token_admission WHERE realm_id=$1",
    )
    .bind(f.realm)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((rows, attempts), (1, 1));
}

#[sqlx::test]
async fn owner_admission_counts_approved_codes_until_consumption_and_cancel_frees_pending(
    pool: PgPool,
) {
    let f = Fixture::new(&pool, false).await;
    let first = f.prepare().await.unwrap();
    let second = f.prepare().await.unwrap();
    let third = f.prepare().await.unwrap();
    let code = f.approve(&first).await;
    assert!(matches!(f.prepare().await, Err(Error::RateLimited)));
    f.service
        .cancel(
            &f.current,
            &f.browser,
            second.handle(),
            second.authorization(),
        )
        .await
        .unwrap();
    let replacement = f.prepare().await.unwrap();
    assert!(matches!(f.prepare().await, Err(Error::RateLimited)));
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
    f.prepare().await.unwrap();
    f.service
        .cancel(
            &f.current,
            &f.browser,
            third.handle(),
            third.authorization(),
        )
        .await
        .unwrap();
    f.service
        .cancel(
            &f.current,
            &f.browser,
            replacement.handle(),
            replacement.authorization(),
        )
        .await
        .unwrap();
}

#[sqlx::test]
async fn infrastructure_failures_are_not_invalid_credentials(pool: PgPool) {
    let f = Fixture::new(&pool, false).await;
    sqlx::query("DROP TABLE auth_issuer_token_admission")
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        f.store
            .admit_issuer_redemption(f.service.authority(), [9; 32])
            .await,
        Err(Error::Unavailable)
    ));
    assert!(matches!(
        f.service
            .redeem(
                &f.authentication(),
                &Secret::generate().unwrap(),
                &f.redirect,
                &f.pkce,
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::Unavailable)
    ));
}
