use super::*;

#[sqlx::test]
async fn same_native_and_consumer_ids_in_two_real_realms_cannot_share_credentials_or_subjects(
    pool: PgPool,
) {
    let id = Uuid::new_v4();
    let reader = Uuid::new_v4();
    let a = Fixture::with_client(pool.clone(), id).await;
    let b = Fixture::with_client(pool, id).await;
    let ca = Consumer::with_client(&a, reader).await;
    ca.enable(&a).await;
    let cb = Consumer::with_client(&b, reader).await;
    cb.enable(&b).await;
    let ta = issued(&a).await;
    let tb = issued(&b).await;
    let aa = ca.inspect(&a, ta.access_token()).await.unwrap().unwrap();
    let ab = cb.inspect(&b, tb.access_token()).await.unwrap().unwrap();
    assert_ne!(aa.access().subject(), ab.access().subject());
    assert!(ca.inspect(&a, tb.access_token()).await.unwrap().is_none());
    assert!(cb.inspect(&b, ta.access_token()).await.unwrap().is_none());
    assert!(matches!(
        ca.service(&a)
            .introspect_access(&cb.authentication(), &ta.access_token().into(), "127.0.0.1")
            .await,
        Err(IssuerTokenError::InvalidClient)
    ));
    a.base
        .store
        .disable_issuer_native_consumer(&a.base.authority, reader, id)
        .await
        .unwrap();
    assert!(ca.inspect(&a, ta.access_token()).await.unwrap().is_none());
    assert!(cb.inspect(&b, tb.access_token()).await.unwrap().is_some());
}

#[sqlx::test]
async fn valid_confidential_authentication_without_this_exact_audience_permission_discloses_no_claims(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let allowed = Consumer::new(&f).await;
    allowed.enable(&f).await;
    let other = Consumer::new(&f).await;
    let token = issued(&f).await;
    let audience = f
        .base
        .store
        .configure_issuer_client(
            &IssuerClientRegistration::public_native_refresh_loopback(
                f.base.authority.realm(),
                Uuid::new_v4(),
                &["http://127.0.0.1/cb"],
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let permission = f
        .base
        .store
        .configure_issuer_native_consumer(
            &IssuerNativeConsumerPolicy::new(
                f.base.authority.clone(),
                other.policy.consumer().clone(),
                audience,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    f.base
        .store
        .enable_issuer_native_consumer(&permission)
        .await
        .unwrap();
    assert!(
        other
            .inspect(&f, token.access_token())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        allowed
            .inspect(&f, token.access_token())
            .await
            .unwrap()
            .is_some()
    );
    let status = IssuerTokenManagement::new(f.base.authority.clone(), f.base.store.clone());
    assert!(
        status
            .introspect_access(
                &allowed.authentication(),
                &token.access_token().into(),
                "127.0.0.1"
            )
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test]
async fn consumer_storage_fault_is_an_error_and_never_inactive_success(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let c = Consumer::new(&f).await;
    c.enable(&f).await;
    let token = issued(&f).await;
    sqlx::query(
        "ALTER TABLE auth_issuer_native_consumers RENAME COLUMN enabled TO unavailable_enabled",
    )
    .execute(&f.base.pool)
    .await
    .unwrap();
    assert!(matches!(
        c.inspect(&f, token.access_token()).await,
        Err(IssuerTokenError::Unavailable)
    ));
    sqlx::query(
        "ALTER TABLE auth_issuer_native_consumers RENAME COLUMN unavailable_enabled TO enabled",
    )
    .execute(&f.base.pool)
    .await
    .unwrap();
    assert!(c.inspect(&f, token.access_token()).await.unwrap().is_some());
}

#[sqlx::test]
async fn unauthorized_consumer_permission_does_not_hide_an_independent_owner_storage_fault(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let c = Consumer::new(&f).await;
    let token = issued(&f).await;
    assert!(c.inspect(&f, token.access_token()).await.unwrap().is_none());
    sqlx::query("ALTER TABLE auth_users RENAME COLUMN email TO unavailable_email")
        .execute(&f.base.pool)
        .await
        .unwrap();
    assert!(matches!(
        c.inspect(&f, token.access_token()).await,
        Err(IssuerTokenError::Unavailable)
    ));
    sqlx::query("ALTER TABLE auth_users RENAME COLUMN unavailable_email TO email")
        .execute(&f.base.pool)
        .await
        .unwrap();
    assert!(c.inspect(&f, token.access_token()).await.unwrap().is_none());
    c.enable(&f).await;
    assert!(c.inspect(&f, token.access_token()).await.unwrap().is_some());
}
