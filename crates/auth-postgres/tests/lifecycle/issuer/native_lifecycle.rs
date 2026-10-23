use super::*;
use auth_core::Secret;

#[sqlx::test]
async fn concurrent_native_subjects_remain_stable_and_real_owner_erasure_cascades(pool: PgPool) {
    let (store, realm, owner) = setup(&pool).await;
    let client = store
        .configure_issuer_client(&native(realm, Uuid::new_v4(), "http://127.0.0.1/cb"))
        .await
        .unwrap();
    let (first, second) = tokio::join!(
        store.issuer_subject(&client, owner),
        store.issuer_subject(&client, owner)
    );
    let subject = first.unwrap();
    assert_eq!(second.unwrap(), subject);
    let (_, other_realm, other_owner) = setup(&pool).await;
    let other = store
        .configure_issuer_client(&native(other_realm, client.client(), "http://127.0.0.1/cb"))
        .await
        .unwrap();
    let other_subject = store.issuer_subject(&other, other_owner).await.unwrap();
    assert_ne!(subject, other_subject);
    let session = crate::support::signed_in(&store, realm, "owner@example.test").await;
    let token = Secret::generate().unwrap();
    let browser = Secret::generate().unwrap();
    store
        .begin_account_deletion(
            realm,
            session.verifier(),
            token.verifier(),
            browser.verifier(),
        )
        .await
        .unwrap();
    store
        .finish_account_deletion(
            realm,
            session.verifier(),
            token.verifier(),
            browser.verifier(),
        )
        .await
        .unwrap();
    assert!(store.issuer_subject(&client, owner).await.is_err());
    assert_eq!(
        store.issuer_subject(&other, other_owner).await.unwrap(),
        other_subject
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM auth_issuer_subjects")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    let session = crate::support::signed_in(&store, realm, "owner@example.test").await;
    let replacement = store.authenticate(realm, session.verifier()).await.unwrap();
    assert_ne!(replacement.id, owner);
    assert_ne!(
        store.issuer_subject(&client, replacement.id).await.unwrap(),
        subject
    );
}
