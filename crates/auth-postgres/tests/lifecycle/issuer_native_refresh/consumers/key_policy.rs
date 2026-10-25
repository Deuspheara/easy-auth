use super::*;

#[sqlx::test]
async fn retained_access_key_survives_normal_rotation_but_not_explicit_key_disable(pool: PgPool) {
    let mut f = Fixture::new(pool.clone()).await;
    let c = Consumer::new(&f).await;
    c.enable(&f).await;
    // Reuse the existing normal signing fixture, with no new key producer.
    let next = crate::support::issuer_tokens::Tokens::new(pool).await;
    let now: i64 =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&f.base.pool)
            .await
            .unwrap();
    f.base
        .store
        .publish_issuer_key(
            &IssuerKeyPublication::new(
                f.base.authority.clone(),
                next.key.public_key().unwrap(),
                now - 1_000_000,
                now + 3_600_000_000,
                now + 3_900_000_000,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    // Observe the real configured prepublication interval. Do not alter a stored
    // readiness deadline or weaken the production activation check for this case.
    tokio::time::sleep(std::time::Duration::from_secs(
        (ISSUER_KEY_PROPAGATION_SECONDS + 1).try_into().unwrap(),
    ))
    .await;
    // Begin the native owner operation with a genuine newly authenticated session
    // after publication propagation; never rewrite its authentication timestamp.
    f.base.current = crate::support::signed_in(
        &f.base.store,
        f.base.authority.realm(),
        "owner@example.test",
    )
    .await;
    let token = issued(&f).await;
    f.base
        .store
        .activate_issuer_key(&f.base.authority, next.key.id())
        .await
        .unwrap();
    assert!(c.inspect(&f, token.access_token()).await.unwrap().is_some());
    f.base
        .store
        .disable_issuer_key(&f.base.authority, f.base.key.id())
        .await
        .unwrap();
    assert!(c.inspect(&f, token.access_token()).await.unwrap().is_none());
}

#[sqlx::test]
async fn disabling_native_grant_policy_prevents_active_consumer_metadata(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let c = Consumer::new(&f).await;
    c.enable(&f).await;
    let token = issued(&f).await;
    assert!(c.inspect(&f, token.access_token()).await.unwrap().is_some());
    f.base
        .store
        .disable_issuer_native_refresh_policy(&f.base.authority, f.policy.client().client())
        .await
        .unwrap();
    assert!(c.inspect(&f, token.access_token()).await.unwrap().is_none());
    f.refresher()
        .revoke(
            &f.authentication(),
            &token.refresh_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    assert!(c.inspect(&f, token.access_token()).await.unwrap().is_none());
}
