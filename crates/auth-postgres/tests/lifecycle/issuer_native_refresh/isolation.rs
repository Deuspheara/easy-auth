use super::*;

#[sqlx::test]
async fn native_policy_isolates_realms_issuers_clients_and_entire_definition(pool: PgPool) {
    let (store, input) = setup(&pool).await;
    let saved = store
        .configure_issuer_native_refresh_policy(&input)
        .await
        .unwrap();
    store
        .enable_issuer_native_refresh_policy(&saved)
        .await
        .unwrap();
    let other_issuer =
        IssuerAuthority::new(saved.authority().realm(), "https://other.example").unwrap();
    let other_policy =
        IssuerNativeRefreshPolicy::new(other_issuer.clone(), saved.client().clone(), 3600, 600)
            .unwrap();
    assert!(
        store
            .check_issuer_native_refresh_policy(
                &other_policy
                    .clone()
                    .with_persisted_revision(saved.revision())
                    .unwrap()
            )
            .await
            .is_err()
    );
    let other_policy = store
        .configure_issuer_native_refresh_policy(&other_policy)
        .await
        .unwrap();
    store
        .enable_issuer_native_refresh_policy(&other_policy)
        .await
        .unwrap();
    let changed = IssuerNativeRefreshPolicy::new(
        saved.authority().clone(),
        saved.client().clone(),
        86400,
        1800,
    )
    .unwrap()
    .with_persisted_revision(saved.revision())
    .unwrap();
    assert!(
        store
            .check_issuer_native_refresh_policy(&changed)
            .await
            .is_err()
    );
    assert!(
        store
            .enable_issuer_native_refresh_policy(&changed)
            .await
            .is_err()
    );
    let (other_store, other_realm) = crate::support::realm(pool.clone()).await;
    let other_client = other_store
        .configure_issuer_client(
            &IssuerClientRegistration::public_native_refresh_loopback(
                other_realm,
                saved.client().client(),
                &["http://127.0.0.1/cb"],
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let realm_policy = IssuerNativeRefreshPolicy::new(
        IssuerAuthority::new(other_realm, saved.authority().issuer()).unwrap(),
        other_client,
        86400,
        3600,
    )
    .unwrap();
    assert!(
        other_store
            .load_issuer_native_refresh_policy(realm_policy.authority(), saved.client().client())
            .await
            .is_err()
    );
    let realm_policy = other_store
        .configure_issuer_native_refresh_policy(&realm_policy)
        .await
        .unwrap();
    other_store
        .enable_issuer_native_refresh_policy(&realm_policy)
        .await
        .unwrap();
    store
        .disable_issuer_native_refresh_policy(saved.authority(), Uuid::new_v4())
        .await
        .unwrap();
    store
        .check_issuer_native_refresh_policy(&saved)
        .await
        .unwrap();
    store
        .disable_issuer_native_refresh_policy(saved.authority(), saved.client().client())
        .await
        .unwrap();
    store
        .check_issuer_native_refresh_policy(&other_policy)
        .await
        .unwrap();
    other_store
        .check_issuer_native_refresh_policy(&realm_policy)
        .await
        .unwrap();
    sqlx::query("DELETE FROM auth_issuer_clients WHERE realm_id=$1 AND id=$2")
        .bind(saved.authority().realm())
        .bind(saved.client().client())
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        store
            .load_issuer_native_refresh_policy(&other_issuer, saved.client().client())
            .await
            .is_err()
    );
    other_store
        .check_issuer_native_refresh_policy(&realm_policy)
        .await
        .unwrap();
}

#[sqlx::test]
async fn native_policy_storage_rejects_invalid_bounds_and_reports_missing_storage_as_unavailable(
    pool: PgPool,
) {
    let (store, input) = setup(&pool).await;
    let saved = store
        .configure_issuer_native_refresh_policy(&input)
        .await
        .unwrap();
    store
        .enable_issuer_native_refresh_policy(&saved)
        .await
        .unwrap();
    for change in [
        "lifetime_seconds=0",
        "lifetime_seconds=604801",
        "idle_seconds=0",
        "idle_seconds=86401",
        "lifetime_seconds=10,idle_seconds=11",
        "revision='00000000-0000-0000-0000-000000000000'",
    ] {
        assert!(
            sqlx::raw_sql(&format!(
                "UPDATE auth_issuer_native_refresh_policies SET {change}"
            ))
            .execute(&pool)
            .await
            .is_err()
        );
    }
    store
        .check_issuer_native_refresh_policy(&saved)
        .await
        .unwrap();
    sqlx::raw_sql("ALTER TABLE auth_issuer_native_refresh_policies RENAME TO owned_missing_policy")
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        store.check_issuer_native_refresh_policy(&saved).await,
        Err(Error::Unavailable)
    ));
    assert!(matches!(
        store
            .load_issuer_native_refresh_policy(saved.authority(), saved.client().client())
            .await,
        Err(Error::Unavailable)
    ));
}
