use super::*;

#[sqlx::test]
async fn consumer_permission_is_initially_disabled_exact_and_restartable_without_implicit_enable(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let c = Consumer::new(&f).await;
    let token = issued(&f).await;
    assert!(c.inspect(&f, token.access_token()).await.unwrap().is_none());
    assert!(
        f.base
            .store
            .load_issuer_native_consumer(
                &f.base.authority,
                c.policy.consumer().client(),
                c.policy.audience().client()
            )
            .await
            .is_err()
    );
    c.enable(&f).await;
    assert!(c.inspect(&f, token.access_token()).await.unwrap().is_some());
    let restarted = easy_auth_postgres::Postgres::new(f.base.pool.clone());
    assert_eq!(
        restarted
            .load_issuer_native_consumer(
                &f.base.authority,
                c.policy.consumer().client(),
                c.policy.audience().client()
            )
            .await
            .unwrap(),
        c.policy
    );
    restarted
        .disable_issuer_native_consumer(
            &f.base.authority,
            c.policy.consumer().client(),
            c.policy.audience().client(),
        )
        .await
        .unwrap();
    assert!(c.inspect(&f, token.access_token()).await.unwrap().is_none());
    assert!(
        restarted
            .enable_issuer_native_consumer(&c.policy)
            .await
            .is_err()
    );
    let next = restarted
        .configure_issuer_native_consumer(&c.policy)
        .await
        .unwrap();
    assert_ne!(next.revision(), c.policy.revision());
    assert!(c.inspect(&f, token.access_token()).await.unwrap().is_none());
    restarted
        .enable_issuer_native_consumer(&next)
        .await
        .unwrap();
    assert!(c.inspect(&f, token.access_token()).await.unwrap().is_some());
}

#[sqlx::test]
async fn consumer_or_audience_revision_changes_require_explicit_current_rebinding(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let c = Consumer::new(&f).await;
    c.enable(&f).await;
    let token = issued(&f).await;
    let new_reader = f
        .base
        .store
        .configure_issuer_client(c.policy.consumer())
        .await
        .unwrap();
    assert!(c.inspect(&f, token.access_token()).await.unwrap().is_none());
    assert!(
        f.base
            .store
            .enable_issuer_native_consumer(&c.policy)
            .await
            .is_err()
    );
    let rebound = f
        .base
        .store
        .configure_issuer_native_consumer(
            &IssuerNativeConsumerPolicy::new(
                f.base.authority.clone(),
                new_reader,
                f.policy.client().clone(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    f.base
        .store
        .enable_issuer_native_consumer(&rebound)
        .await
        .unwrap();
    assert!(c.inspect(&f, token.access_token()).await.unwrap().is_some());
    let _changed = f
        .base
        .store
        .configure_issuer_client(f.policy.client())
        .await
        .unwrap();
    assert!(c.inspect(&f, token.access_token()).await.unwrap().is_none());
    assert!(
        f.base
            .store
            .enable_issuer_native_consumer(&rebound)
            .await
            .is_err()
    );
}
