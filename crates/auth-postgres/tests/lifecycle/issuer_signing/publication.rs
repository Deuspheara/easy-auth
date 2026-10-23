use super::*;

#[sqlx::test]
async fn expired_active_publication_cannot_reuse_old_bootstrap_or_propagation_age(pool: PgPool) {
    let (store, authority, input) = setup(&pool).await;
    store.publish_issuer_key(&input).await.unwrap();
    let revision = store
        .activate_issuer_key(&authority, input.key().id())
        .await
        .unwrap();
    store
        .enable_issuer_signing(&authority, revision)
        .await
        .unwrap();
    // Reaffirming an uninterrupted live publication does not restart propagation.
    store.publish_issuer_key(&input).await.unwrap();
    store.load_issuer_signing(&authority).await.unwrap();
    // Isolate a previously expired publication with valid historical windows.
    // Reopening this same active ID must be treated as fresh public availability.
    sqlx::query("UPDATE auth_issuer_keys SET sign_from_us=0,sign_until_us=1,verify_until_us=300000001 WHERE realm_id=$1 AND issuer=$2 AND id=$3")
        .bind(authority.realm()).bind(authority.issuer()).bind(input.key().id()).execute(&pool).await.unwrap();
    store.publish_issuer_key(&input).await.unwrap();
    assert_eq!(store.issuer_public_keys(&authority).await.unwrap().len(), 1);
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
    let revision: Uuid = sqlx::query_scalar(
        "SELECT revision FROM auth_issuer_key_sets WHERE realm_id=$1 AND issuer=$2",
    )
    .bind(authority.realm())
    .bind(authority.issuer())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(matches!(
        store.enable_issuer_signing(&authority, revision).await,
        Err(Error::Unauthorized)
    ));
    allow_rotation(&pool, &input).await;
    store
        .activate_issuer_key(&authority, input.key().id())
        .await
        .unwrap();
    assert_eq!(
        store
            .load_issuer_signing(&authority)
            .await
            .unwrap()
            .publication(),
        &input
    );
}

#[sqlx::test]
async fn live_key_bound_applies_to_new_reenabled_and_reopened_expired_publications(pool: PgPool) {
    let (store, authority, first) = setup(&pool).await;
    store.publish_issuer_key(&first).await.unwrap();
    let second = alias(&first);
    let third = alias(&first);
    let fourth = alias(&first);
    let fifth = alias(&first);
    for input in [&second, &third, &fourth] {
        store.publish_issuer_key(input).await.unwrap();
    }
    assert!(matches!(
        store.publish_issuer_key(&fifth).await,
        Err(Error::RateLimited)
    ));
    store
        .disable_issuer_key(&authority, second.key().id())
        .await
        .unwrap();
    store.publish_issuer_key(&fifth).await.unwrap();
    assert!(matches!(
        store.enable_issuer_key(&second).await,
        Err(Error::RateLimited)
    ));
    // Historical expiry with the original valid ordered windows; reopening must
    // not bypass capacity merely because this identifier already has a row.
    let expired = alias(&first);
    sqlx::query("INSERT INTO auth_issuer_keys(realm_id,issuer,id,public_jwk,sign_from_us,sign_until_us,verify_until_us) VALUES($1,$2,$3,$4,0,1,300000001)")
        .bind(authority.realm()).bind(authority.issuer()).bind(expired.key().id()).bind(expired.key().document()).execute(&pool).await.unwrap();
    assert!(matches!(
        store.publish_issuer_key(&expired).await,
        Err(Error::RateLimited)
    ));
    assert_eq!(store.issuer_public_keys(&authority).await.unwrap().len(), 4);
}

#[sqlx::test]
async fn concurrent_last_publication_slot_has_only_one_committed_winner(pool: PgPool) {
    let (store, authority, first) = setup(&pool).await;
    let second = alias(&first);
    let third = alias(&first);
    for input in [&first, &second, &third] {
        store.publish_issuer_key(input).await.unwrap();
    }
    let fourth = alias(&first);
    let fifth = alias(&first);
    // Ordinary database-only metadata admission, not signature concurrency.
    let (a, b) = tokio::join!(
        store.publish_issuer_key(&fourth),
        store.publish_issuer_key(&fifth)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(
        usize::from(matches!(a, Err(Error::RateLimited)))
            + usize::from(matches!(b, Err(Error::RateLimited))),
        1
    );
    assert_eq!(store.issuer_public_keys(&authority).await.unwrap().len(), 4);
}
