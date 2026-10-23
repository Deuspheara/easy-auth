use super::*;

#[sqlx::test]
async fn native_offline_policy_starts_disabled_and_replacement_never_clears_disable(pool: PgPool) {
    let (store, input) = setup(&pool).await;
    let saved = store
        .configure_issuer_native_refresh_policy(&input)
        .await
        .unwrap();
    assert_ne!(saved.revision(), input.revision());
    assert!(matches!(
        store.check_issuer_native_refresh_policy(&saved).await,
        Err(Error::Unauthorized)
    ));
    assert!(
        store
            .load_issuer_native_refresh_policy(saved.authority(), saved.client().client())
            .await
            .is_err()
    );
    assert!(
        store
            .enable_issuer_native_refresh_policy(&input)
            .await
            .is_err()
    );
    store
        .enable_issuer_native_refresh_policy(&saved)
        .await
        .unwrap();
    assert_eq!(
        store
            .load_issuer_native_refresh_policy(saved.authority(), saved.client().client())
            .await
            .unwrap(),
        saved
    );
    store
        .check_issuer_native_refresh_policy(&saved)
        .await
        .unwrap();
    store
        .disable_issuer_native_refresh_policy(saved.authority(), saved.client().client())
        .await
        .unwrap();
    assert!(
        store
            .enable_issuer_native_refresh_policy(&saved)
            .await
            .is_err()
    );
    let replacement = store
        .configure_issuer_native_refresh_policy(&saved)
        .await
        .unwrap();
    assert!(
        store
            .check_issuer_native_refresh_policy(&replacement)
            .await
            .is_err()
    );
    store
        .enable_issuer_native_refresh_policy(&replacement)
        .await
        .unwrap();
    store
        .check_issuer_native_refresh_policy(&replacement)
        .await
        .unwrap();
    assert!(
        store
            .check_issuer_native_refresh_policy(&saved)
            .await
            .is_err()
    );
    // Configuration alone creates no authentication/consent authority.
    for table in [
        "auth_users",
        "auth_sessions",
        "auth_issuer_subjects",
        "auth_issuer_authorizations",
        "auth_issuer_access_tokens",
    ] {
        assert_eq!(
            sqlx::query_scalar::<_, i64>(&format!("SELECT count(*) FROM {table}"))
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
    }
}

#[sqlx::test]
async fn policy_requires_full_current_enabled_client_and_rolls_back_storage_failure(pool: PgPool) {
    let (store, input) = setup(&pool).await;
    let saved = store
        .configure_issuer_native_refresh_policy(&input)
        .await
        .unwrap();
    store
        .enable_issuer_native_refresh_policy(&saved)
        .await
        .unwrap();
    let current = store.configure_issuer_client(saved.client()).await.unwrap();
    assert!(
        store
            .check_issuer_native_refresh_policy(&saved)
            .await
            .is_err()
    );
    assert!(
        store
            .load_issuer_native_refresh_policy(saved.authority(), current.client())
            .await
            .is_err()
    );
    assert!(
        store
            .configure_issuer_native_refresh_policy(&saved)
            .await
            .is_err()
    );
    let changed =
        IssuerNativeRefreshPolicy::new(saved.authority().clone(), current, 86400, 1800).unwrap();
    sqlx::raw_sql("ALTER TABLE auth_issuer_native_refresh_policies ADD CONSTRAINT owned_policy_fault CHECK (idle_seconds=3600) NOT VALID").execute(&pool).await.unwrap();
    assert!(matches!(
        store.configure_issuer_native_refresh_policy(&changed).await,
        Err(Error::Unavailable)
    ));
    let revision: Uuid =
        sqlx::query_scalar("SELECT revision FROM auth_issuer_native_refresh_policies")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(revision, saved.revision());
    sqlx::raw_sql(
        "ALTER TABLE auth_issuer_native_refresh_policies DROP CONSTRAINT owned_policy_fault",
    )
    .execute(&pool)
    .await
    .unwrap();
    let current = store
        .configure_issuer_native_refresh_policy(&changed)
        .await
        .unwrap();
    store
        .check_issuer_native_refresh_policy(&current)
        .await
        .unwrap();
    store
        .disable_issuer_client(current.authority().realm(), current.client().client())
        .await
        .unwrap();
    assert!(
        store
            .check_issuer_native_refresh_policy(&current)
            .await
            .is_err()
    );
    assert!(
        store
            .enable_issuer_native_refresh_policy(&current)
            .await
            .is_err()
    );
    store
        .disable_issuer_native_refresh_policy(current.authority(), current.client().client())
        .await
        .unwrap();
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT enabled FROM auth_issuer_native_refresh_policies")
            .fetch_one(&pool)
            .await
            .unwrap()
    );
}
