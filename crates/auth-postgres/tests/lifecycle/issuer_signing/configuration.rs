use super::*;

#[sqlx::test]
async fn trusted_publication_bootstrap_and_enable_remain_separate_and_disable_persists(
    pool: PgPool,
) {
    let (store, authority, input) = setup(&pool).await;
    let published = store.publish_issuer_key(&input).await.unwrap();
    assert!(matches!(
        store.load_issuer_signing(&authority).await,
        Err(Error::Unavailable)
    ));
    assert_eq!(
        store.issuer_public_keys(&authority).await.unwrap(),
        [input.key().clone()]
    );
    let revision = store
        .activate_issuer_key(&authority, input.key().id())
        .await
        .unwrap();
    assert!(matches!(
        store.load_issuer_signing(&authority).await,
        Err(Error::Unavailable)
    ));
    store
        .enable_issuer_signing(&authority, revision)
        .await
        .unwrap();
    let active = store.load_issuer_signing(&authority).await.unwrap();
    assert_eq!(active.publication(), &published);
    store.disable_issuer_signing(&authority).await.unwrap();
    let unchanged = store.publish_issuer_key(&input).await.unwrap();
    assert_eq!(unchanged, published);
    assert!(matches!(
        store.load_issuer_signing(&authority).await,
        Err(Error::Unavailable)
    ));
    assert!(matches!(
        store.enable_issuer_signing(&authority, revision).await,
        Err(Error::Unauthorized)
    ));
    // Reaffirming the same key is not replacement propagation or implicit enable.
    let current = store
        .activate_issuer_key(&authority, input.key().id())
        .await
        .unwrap();
    store
        .enable_issuer_signing(&authority, current)
        .await
        .unwrap();
    store
        .disable_issuer_key(&authority, input.key().id())
        .await
        .unwrap();
    assert!(store.load_issuer_signing(&authority).await.is_err());
    let disabled = store.publish_issuer_key(&input).await.unwrap();
    assert!(
        store
            .activate_issuer_key(&authority, input.key().id())
            .await
            .is_err()
    );
    store.enable_issuer_key(&disabled).await.unwrap();
    assert!(matches!(
        store.load_issuer_signing(&authority).await,
        Err(Error::Unavailable)
    ));
    assert!(matches!(
        store
            .activate_issuer_key(&authority, input.key().id())
            .await,
        Err(Error::Unauthorized)
    ));
    allow_rotation(&pool, &input).await;
    let current = store
        .activate_issuer_key(&authority, input.key().id())
        .await
        .unwrap();
    store
        .enable_issuer_signing(&authority, current)
        .await
        .unwrap();
    assert_eq!(
        store
            .load_issuer_signing(&authority)
            .await
            .unwrap()
            .publication(),
        &published
    );
    let (users, sessions): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_sessions)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((users, sessions), (0, 0));
}

#[sqlx::test]
async fn actual_replacement_requires_prepublishing_and_retains_the_old_public_key(pool: PgPool) {
    let (store, authority, first) = setup(&pool).await;
    store.publish_issuer_key(&first).await.unwrap();
    let revision = store
        .activate_issuer_key(&authority, first.key().id())
        .await
        .unwrap();
    store
        .enable_issuer_signing(&authority, revision)
        .await
        .unwrap();
    let second = publication(&pool, &authority).await;
    store.publish_issuer_key(&second).await.unwrap();
    assert!(matches!(
        store
            .activate_issuer_key(&authority, second.key().id())
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(
        store
            .load_issuer_signing(&authority)
            .await
            .unwrap()
            .publication()
            .key(),
        first.key()
    );
    assert_eq!(store.issuer_public_keys(&authority).await.unwrap().len(), 2);
    allow_rotation(&pool, &second).await;
    store
        .activate_issuer_key(&authority, second.key().id())
        .await
        .unwrap();
    assert_eq!(
        store
            .load_issuer_signing(&authority)
            .await
            .unwrap()
            .publication()
            .key(),
        second.key()
    );
    assert!(
        store
            .issuer_public_keys(&authority)
            .await
            .unwrap()
            .contains(first.key())
    );
    let shorter = IssuerKeyPublication::new(
        authority.clone(),
        first.key().clone(),
        first.sign_from_us(),
        first.sign_until_us() - 100_000_000,
        first.verify_until_us() - 100_000_000,
    )
    .unwrap();
    let retained = store.publish_issuer_key(&shorter).await.unwrap();
    assert_eq!(retained.verify_until_us(), first.verify_until_us());
}

#[sqlx::test]
async fn same_key_identifier_cannot_replace_material_or_cross_issuer_and_realm_namespaces(
    pool: PgPool,
) {
    let (store, authority, first) = setup(&pool).await;
    store.publish_issuer_key(&first).await.unwrap();
    let revision = store
        .activate_issuer_key(&authority, first.key().id())
        .await
        .unwrap();
    store
        .enable_issuer_signing(&authority, revision)
        .await
        .unwrap();
    let second = publication(&pool, &authority).await;
    let mut changed = second.key().document().clone();
    changed["kid"] = serde_json::json!(first.key().id());
    let different = IssuerPublicKey::from_json(&serde_json::to_vec(&changed).unwrap()).unwrap();
    let collision = IssuerKeyPublication::new(
        authority.clone(),
        different,
        first.sign_from_us(),
        first.sign_until_us(),
        first.verify_until_us(),
    )
    .unwrap();
    assert!(matches!(
        store.publish_issuer_key(&collision).await,
        Err(Error::InvalidInput)
    ));
    assert_eq!(
        store
            .load_issuer_signing(&authority)
            .await
            .unwrap()
            .revision(),
        revision
    );
    for other in [
        IssuerAuthority::new(authority.realm(), "https://other.example").unwrap(),
        IssuerAuthority::new(Uuid::new_v4(), authority.issuer()).unwrap(),
    ] {
        assert!(store.load_issuer_signing(&other).await.is_err());
        assert!(store.issuer_public_keys(&other).await.is_err());
        assert!(
            store
                .disable_issuer_key(&other, first.key().id())
                .await
                .is_err()
        );
    }
    let error=sqlx::query("UPDATE auth_issuer_keys SET public_jwk=jsonb_set(public_jwk,'{alg}','null'::jsonb) WHERE realm_id=$1")
        .bind(authority.realm()).execute(&pool).await.unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23514")
    );
}
