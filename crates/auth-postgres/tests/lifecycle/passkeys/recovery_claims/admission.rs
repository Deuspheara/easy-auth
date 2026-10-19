use super::*;

#[sqlx::test(migrations = "./migrations")]
async fn continuation_budget_and_erasure_are_owner_scoped_even_for_a_shared_browser(pool: PgPool) {
    let f = Claims::new(pool.clone(), false).await;
    let peer = Claims::in_realm(pool.clone(), false, Some(f.f.realm)).await;
    let claim = f
        .flow
        .begin(f.owner, &f.code, &f.browser, SOURCE)
        .await
        .unwrap();
    let other = peer
        .flow
        .begin(peer.owner, &peer.code, &f.browser, SOURCE)
        .await
        .unwrap();
    for _ in 0..10 {
        f.flow
            .status(f.owner, &f.browser, SOURCE, claim.id)
            .await
            .unwrap();
    }
    assert!(matches!(
        f.flow.status(f.owner, &f.browser, SOURCE, claim.id).await,
        Err(Error::RateLimited)
    ));
    peer.flow
        .status(peer.owner, &f.browser, SOURCE, other.id)
        .await
        .unwrap();
    let query = "SELECT attempts FROM auth_rate_buckets WHERE realm_id=$1 AND dimension='passkey_recovery_browser' AND key_hash=sha256(uuid_send($2)||$3||convert_to($4,'UTF8'))";
    let before: i32 = sqlx::query_scalar(query)
        .bind(f.f.realm)
        .bind(peer.owner)
        .bind(f.browser.verifier().as_slice())
        .bind(f.f.service.rp_id())
        .fetch_one(&pool)
        .await
        .unwrap();
    let (token, browser) =
        crate::account::deletion_proof(&f.f.store, f.f.realm, f.f.session.verifier()).await;
    f.f.store
        .finish_account_deletion(
            f.f.realm,
            f.f.session.verifier(),
            token.verifier(),
            browser.verifier(),
        )
        .await
        .unwrap();
    let after: i32 = sqlx::query_scalar(query)
        .bind(f.f.realm)
        .bind(peer.owner)
        .bind(f.browser.verifier().as_slice())
        .bind(f.f.service.rp_id())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        before, after,
        "erasure must not clear another owner's continuation budget"
    );
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM auth_rate_buckets WHERE realm_id=$1 AND dimension='passkey_recovery_browser'").bind(f.f.realm).fetch_one(&pool).await.unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        peer.flow
            .resume(peer.owner, &f.browser, SOURCE)
            .await
            .unwrap()
            .id,
        other.id
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn valid_browser_continuation_survives_exhausted_code_verification_budget(pool: PgPool) {
    let f = Claims::new(pool, true).await;
    let claim = f
        .flow
        .begin(f.owner, &f.code, &f.browser, SOURCE)
        .await
        .unwrap();
    let wrong = Secret::generate().unwrap();
    for _ in 0..9 {
        assert!(matches!(
            f.flow.begin(f.owner, &wrong, &f.browser, SOURCE).await,
            Err(Error::Unauthorized)
        ));
    }
    assert!(matches!(
        f.flow.begin(f.owner, &f.code, &f.browser, SOURCE).await,
        Err(Error::RateLimited)
    ));
    let current = f
        .flow
        .status(f.owner, &f.browser, SOURCE, claim.id)
        .await
        .unwrap();
    assert_eq!(current.id, claim.id);
    let resumed = f.flow.resume(f.owner, &f.browser, SOURCE).await.unwrap();
    assert_eq!(resumed.id, claim.id);
    let wrong_browser = Secret::generate().unwrap();
    assert!(matches!(
        f.flow.resume(f.owner, &wrong_browser, SOURCE).await,
        Err(Error::Unauthorized)
    ));
    f.flow
        .cancel(f.owner, &f.browser, SOURCE, claim.id)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn unknown_account_attempts_are_source_admitted_before_lookup(pool: PgPool) {
    let f = Claims::new(pool.clone(), true).await;
    let before = f.snapshot().await;
    for _ in 0..40 {
        assert!(matches!(
            f.flow
                .begin(Uuid::new_v4(), &f.code, &f.browser, SOURCE)
                .await,
            Err(Error::Unauthorized)
        ));
    }
    assert!(matches!(
        f.flow.begin(f.owner, &f.code, &f.browser, SOURCE).await,
        Err(Error::RateLimited)
    ));
    f.unchanged(before).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn exhausted_anonymous_budget_cannot_prevent_genuine_key_cancellation(pool: PgPool) {
    let f = Claims::new(pool.clone(), true).await;
    let claim = f
        .flow
        .begin(f.owner, &f.code, &f.browser, SOURCE)
        .await
        .unwrap();
    let wrong = Secret::generate().unwrap();
    for _ in 0..9 {
        assert!(matches!(
            f.flow.begin(f.owner, &wrong, &f.browser, SOURCE).await,
            Err(Error::Unauthorized)
        ));
    }
    assert!(matches!(
        f.flow.begin(f.owner, &f.code, &f.browser, SOURCE).await,
        Err(Error::RateLimited)
    ));
    f.flow
        .cancel_with_key(&f.f.session, SOURCE, claim.id)
        .await
        .unwrap();
    let cancelled: bool = sqlx::query_scalar(
        "SELECT cancelled_at IS NOT NULL FROM auth_passkey_recovery_claims WHERE realm_id=$1",
    )
    .bind(f.f.realm)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(cancelled);
}
