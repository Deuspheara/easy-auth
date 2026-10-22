use super::*;
use auth_core::{Error, IssuerClientKind, Secret};

#[sqlx::test]
async fn trusted_public_and_confidential_registration_keep_only_verifiers(pool: PgPool) {
    let (store, realm, _) = setup(&pool).await;
    let input = public(realm, Uuid::new_v4(), "https://app.example/cb");
    let c = store.configure_issuer_client(&input).await.unwrap();
    assert_ne!(input.revision(), c.revision());
    assert!(store.check_issuer_client(&input).await.is_err());
    store.check_issuer_client(&c).await.unwrap();
    let secret = Secret::generate().unwrap();
    let confidential = IssuerClientRegistration::confidential(
        realm,
        Uuid::new_v4(),
        &["https://service.example/cb"],
        &secret,
    )
    .unwrap();
    let confidential = store.configure_issuer_client(&confidential).await.unwrap();
    assert_eq!(confidential.kind(), IssuerClientKind::ConfidentialBasic);
    let (method,verifier,consent,subject):(String,Vec<u8>,String,String)=sqlx::query_as("SELECT authentication,secret_verifier,consent,subject_type FROM auth_issuer_clients WHERE realm_id=$1 AND id=$2")
        .bind(realm).bind(confidential.client()).fetch_one(&pool).await.unwrap();
    assert_eq!(method, "client_secret_basic");
    assert_eq!(verifier, secret.verifier());
    assert_eq!(consent, "explicit");
    assert_eq!(subject, "pairwise");
    assert_ne!(verifier, secret.expose().as_bytes());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM auth_sessions")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
}

#[sqlx::test]
async fn replacement_and_disable_cannot_restore_stale_definitions(pool: PgPool) {
    let (store, realm, _) = setup(&pool).await;
    let input = public(realm, Uuid::new_v4(), "https://app.example/cb");
    let first = store.configure_issuer_client(&input).await.unwrap();
    store
        .disable_issuer_client(realm, first.client())
        .await
        .unwrap();
    assert!(matches!(
        store.check_issuer_client(&first).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        store.enable_issuer_client(&first).await,
        Err(Error::Unauthorized)
    ));
    let next = store.configure_issuer_client(&input).await.unwrap();
    assert_ne!(next.revision(), first.revision());
    assert!(store.check_issuer_client(&next).await.is_err());
    store.enable_issuer_client(&next).await.unwrap();
    store.check_issuer_client(&next).await.unwrap();
    assert!(store.enable_issuer_client(&first).await.is_err());
    sqlx::query("UPDATE auth_issuer_clients SET redirect_uris=ARRAY['https://app.example/changed'] WHERE realm_id=$1 AND id=$2")
        .bind(realm).bind(first.client()).execute(&pool).await.unwrap();
    assert!(store.check_issuer_client(&next).await.is_err());
    assert!(store.enable_issuer_client(&next).await.is_err());
}

#[sqlx::test]
async fn configuration_fault_rolls_back_its_new_sector(pool: PgPool) {
    let (store, realm, _) = setup(&pool).await;
    sqlx::raw_sql(
        "ALTER TABLE auth_issuer_clients ADD CONSTRAINT owned_fault CHECK(false) NOT VALID",
    )
    .execute(&pool)
    .await
    .unwrap();
    let input = public(realm, Uuid::new_v4(), "https://app.example/cb");
    assert!(matches!(
        store.configure_issuer_client(&input).await,
        Err(Error::Unavailable)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM auth_issuer_sectors")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM auth_issuer_clients")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
}

#[sqlx::test]
async fn credential_rotation_and_closed_storage_policy_fail_stale_checks(pool: PgPool) {
    let (store, realm, _) = setup(&pool).await;
    let id = Uuid::new_v4();
    let first_secret = Secret::generate().unwrap();
    let second_secret = Secret::generate().unwrap();
    let first = store
        .configure_issuer_client(
            &IssuerClientRegistration::confidential(
                realm,
                id,
                &["https://app.example/cb"],
                &first_secret,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let second = store
        .configure_issuer_client(
            &IssuerClientRegistration::confidential(
                realm,
                id,
                &["https://app.example/cb"],
                &second_secret,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    assert!(store.check_issuer_client(&first).await.is_err());
    store.check_issuer_client(&second).await.unwrap();
    sqlx::query("UPDATE auth_issuer_clients SET secret_verifier=$3 WHERE realm_id=$1 AND id=$2")
        .bind(realm)
        .bind(id)
        .bind(first_secret.verifier().to_vec())
        .execute(&pool)
        .await
        .unwrap();
    assert!(store.check_issuer_client(&second).await.is_err());
    for query in [
        "UPDATE auth_issuer_clients SET authentication='none'",
        "UPDATE auth_issuer_clients SET consent='implicit'",
        "UPDATE auth_issuer_clients SET subject_type='public'",
    ] {
        assert!(sqlx::raw_sql(query).execute(&pool).await.is_err());
    }
}
