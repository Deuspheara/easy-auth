use super::*;
use auth_core::{Error, Secret};

#[sqlx::test]
async fn stable_subjects_follow_hostname_sectors_not_local_user_ids(pool: PgPool) {
    let (store, realm, user) = setup(&pool).await;
    let a = store
        .configure_issuer_client(&public(realm, Uuid::new_v4(), "https://app.example/cb"))
        .await
        .unwrap();
    let b = store
        .configure_issuer_client(&public(
            realm,
            Uuid::new_v4(),
            "https://app.example:8443/other?q=fixed",
        ))
        .await
        .unwrap();
    let other = store
        .configure_issuer_client(&public(realm, Uuid::new_v4(), "https://other.example/cb"))
        .await
        .unwrap();
    let subject = store.issuer_subject(&a, user).await.unwrap();
    assert_ne!(subject, user);
    assert_eq!(store.issuer_subject(&a, user).await.unwrap(), subject);
    assert_eq!(store.issuer_subject(&b, user).await.unwrap(), subject);
    assert_ne!(store.issuer_subject(&other, user).await.unwrap(), subject);
    let session = crate::support::signed_in(&store, realm, "another@example.test").await;
    let another = store.authenticate(realm, session.verifier()).await.unwrap();
    assert_ne!(store.issuer_subject(&a, another.id).await.unwrap(), subject);
}

#[sqlx::test]
async fn same_client_identifier_in_another_realm_cannot_select_foreign_owner(pool: PgPool) {
    let (store, realm, user) = setup(&pool).await;
    let (other_store, other_realm, other_user) = setup(&pool).await;
    let id = Uuid::new_v4();
    let a = store
        .configure_issuer_client(&public(realm, id, "https://app.example/cb"))
        .await
        .unwrap();
    let b = other_store
        .configure_issuer_client(&public(other_realm, id, "https://app.example/cb"))
        .await
        .unwrap();
    assert!(matches!(
        store.issuer_subject(&b, user).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        store.issuer_subject(&a, other_user).await,
        Err(Error::Unauthorized)
    ));
    assert_ne!(
        store.issuer_subject(&a, user).await.unwrap(),
        other_store.issuer_subject(&b, other_user).await.unwrap()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM auth_issuer_subjects")
            .fetch_one(&pool)
            .await
            .unwrap(),
        2
    );
}

#[sqlx::test]
async fn concurrent_clients_in_same_sector_allocate_only_one_subject(pool: PgPool) {
    let (store, realm, user) = setup(&pool).await;
    let a = store
        .configure_issuer_client(&public(realm, Uuid::new_v4(), "https://app.example/cb"))
        .await
        .unwrap();
    let b = store
        .configure_issuer_client(&public(realm, Uuid::new_v4(), "https://app.example/other"))
        .await
        .unwrap();
    let (first, second) = tokio::join!(
        store.issuer_subject(&a, user),
        store.issuer_subject(&b, user)
    );
    assert_eq!(first.unwrap(), second.unwrap());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM auth_issuer_subjects")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
}

#[sqlx::test]
async fn disabled_or_changed_client_and_storage_fault_never_allocate_subject(pool: PgPool) {
    let (store, realm, user) = setup(&pool).await;
    let a = store
        .configure_issuer_client(&public(realm, Uuid::new_v4(), "https://app.example/cb"))
        .await
        .unwrap();
    store
        .disable_issuer_client(realm, a.client())
        .await
        .unwrap();
    assert!(store.issuer_subject(&a, user).await.is_err());
    let b = store.configure_issuer_client(&a).await.unwrap();
    assert!(store.issuer_subject(&b, user).await.is_err());
    store.enable_issuer_client(&b).await.unwrap();
    sqlx::raw_sql(
        "ALTER TABLE auth_issuer_subjects ADD CONSTRAINT owned_fault CHECK(false) NOT VALID",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        store.issuer_subject(&b, user).await,
        Err(Error::Unavailable)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM auth_issuer_subjects")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    sqlx::raw_sql("ALTER TABLE auth_issuer_subjects DROP CONSTRAINT owned_fault")
        .execute(&pool)
        .await
        .unwrap();
    store.issuer_subject(&b, user).await.unwrap();
}

#[sqlx::test]
async fn existing_account_erasure_cascades_only_its_owned_subjects(pool: PgPool) {
    let (store, realm, user) = setup(&pool).await;
    let client = store
        .configure_issuer_client(&public(realm, Uuid::new_v4(), "https://app.example/cb"))
        .await
        .unwrap();
    let old = store.issuer_subject(&client, user).await.unwrap();
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
    assert!(store.issuer_subject(&client, user).await.is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM auth_issuer_subjects")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    let session = crate::support::signed_in(&store, realm, "owner@example.test").await;
    let replacement = store.authenticate(realm, session.verifier()).await.unwrap();
    assert_ne!(replacement.id, user);
    assert_ne!(
        store.issuer_subject(&client, replacement.id).await.unwrap(),
        old
    );
}
