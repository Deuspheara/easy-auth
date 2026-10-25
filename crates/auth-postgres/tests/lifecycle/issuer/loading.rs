use super::*;
use auth_core::{Error, IssuerClientAuthentication, Secret};

#[sqlx::test]
async fn loading_restores_exact_native_and_confidential_metadata_without_reprovisioning(
    pool: PgPool,
) {
    let (store, realm, owner) = setup(&pool).await;
    let secret = Secret::generate().unwrap();
    let confidential = store
        .configure_issuer_client(
            &IssuerClientRegistration::confidential(
                realm,
                Uuid::new_v4(),
                &["https://app.example/cb"],
                &secret,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let native = store
        .configure_issuer_client(&native(realm, Uuid::new_v4(), "http://127.0.0.1:44001/cb"))
        .await
        .unwrap();
    let subject = store.issuer_subject(&native, owner).await.unwrap();
    let before: serde_json::Value =
        sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM auth_issuer_clients c")
            .fetch_one(&pool)
            .await
            .unwrap();
    let restarted = Postgres::new(pool.clone());
    for expected in [&confidential, &native] {
        let loaded = restarted
            .load_issuer_client(realm, expected.client())
            .await
            .unwrap();
        assert_eq!(&loaded, expected);
        restarted.check_issuer_client(&loaded).await.unwrap();
    }
    let loaded = restarted
        .load_issuer_client(realm, confidential.client())
        .await
        .unwrap();
    restarted
        .validate_issuer_client_authentication(
            &loaded,
            &IssuerClientAuthentication::basic(loaded.client(), &secret).unwrap(),
        )
        .await
        .unwrap();
    let loaded = restarted
        .load_issuer_client(realm, native.client())
        .await
        .unwrap();
    assert_eq!(
        restarted.issuer_subject(&loaded, owner).await.unwrap(),
        subject
    );
    let after: serde_json::Value =
        sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM auth_issuer_clients c")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after);
    assert!(matches!(
        restarted
            .load_issuer_client(Uuid::new_v4(), native.client())
            .await,
        Err(Error::Unauthorized)
    ));
    store
        .disable_issuer_client(realm, native.client())
        .await
        .unwrap();
    assert!(matches!(
        restarted.load_issuer_client(realm, native.client()).await,
        Err(Error::Unauthorized)
    ));
    assert!(store.check_issuer_client(&loaded).await.is_err());
    restarted.check_issuer_client(&confidential).await.unwrap();
}

#[sqlx::test]
async fn loading_refuses_corrupt_metadata_without_repair_or_fallback(pool: PgPool) {
    let (store, realm, _) = setup(&pool).await;
    let client = store
        .configure_issuer_client(&public(realm, Uuid::new_v4(), "https://app.example/cb"))
        .await
        .unwrap();
    sqlx::query("UPDATE auth_issuer_clients SET redirect_uris=ARRAY['http://127.0.0.1/cb'] WHERE realm_id=$1 AND id=$2")
        .bind(realm).bind(client.client()).execute(&pool).await.unwrap();
    assert!(matches!(
        store.load_issuer_client(realm, client.client()).await,
        Err(Error::Unavailable)
    ));
    let stored: Vec<String> = sqlx::query_scalar(
        "SELECT redirect_uris FROM auth_issuer_clients WHERE realm_id=$1 AND id=$2",
    )
    .bind(realm)
    .bind(client.client())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored, ["http://127.0.0.1/cb"]);
    let repaired = store.configure_issuer_client(&client).await.unwrap();
    assert_eq!(
        store
            .load_issuer_client(realm, client.client())
            .await
            .unwrap(),
        repaired
    );
}
