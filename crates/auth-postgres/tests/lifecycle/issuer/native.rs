use super::*;
use auth_core::{Error, IssuerClientAuthentication, IssuerRedirectProfile};

#[sqlx::test]
async fn native_port_changes_preserve_registration_and_one_clients_subject_only(pool: PgPool) {
    let (store, realm, owner) = setup(&pool).await;
    let client = store
        .configure_issuer_client(&native(realm, Uuid::new_v4(), "http://127.0.0.1:42001/cb"))
        .await
        .unwrap();
    assert_eq!(
        client.redirect_profile(),
        IssuerRedirectProfile::NativeLoopback
    );
    store.check_issuer_client(&client).await.unwrap();
    let subject = store.issuer_subject(&client, owner).await.unwrap();
    for port in [42001, 42002, 65535] {
        assert!(client.permits_redirect(&format!("http://127.0.0.1:{port}/cb")));
        assert_eq!(store.issuer_subject(&client, owner).await.unwrap(), subject);
    }
    let peer = store
        .configure_issuer_client(&native(realm, Uuid::new_v4(), "http://127.0.0.1:42002/cb"))
        .await
        .unwrap();
    assert_ne!(store.issuer_subject(&peer, owner).await.unwrap(), subject);
    let (other_store, other_realm, other_owner) = setup(&pool).await;
    let other = other_store
        .configure_issuer_client(&native(other_realm, client.client(), "http://127.0.0.1/cb"))
        .await
        .unwrap();
    assert_ne!(
        other_store
            .issuer_subject(&other, other_owner)
            .await
            .unwrap(),
        subject
    );
    assert!(matches!(
        store.issuer_subject(&other, owner).await,
        Err(Error::Unauthorized)
    ));
    let authentication = IssuerClientAuthentication::public(client.client()).unwrap();
    store
        .validate_issuer_client_authentication(&client, &authentication)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM auth_sessions")
            .fetch_one(&pool)
            .await
            .unwrap(),
        2
    );
}

#[sqlx::test]
async fn native_profile_replacement_retains_disable_and_rejects_stale_web_metadata(pool: PgPool) {
    let (store, realm, owner) = setup(&pool).await;
    let id = Uuid::new_v4();
    let web = store
        .configure_issuer_client(&public(realm, id, "https://app.example/cb"))
        .await
        .unwrap();
    let web_subject = store.issuer_subject(&web, owner).await.unwrap();
    store.disable_issuer_client(realm, id).await.unwrap();
    let current = store
        .configure_issuer_client(&native(realm, id, "http://[::1]/cb"))
        .await
        .unwrap();
    assert!(store.check_issuer_client(&current).await.is_err());
    assert!(store.enable_issuer_client(&web).await.is_err());
    store.enable_issuer_client(&current).await.unwrap();
    assert!(store.check_issuer_client(&web).await.is_err());
    let native_subject = store.issuer_subject(&current, owner).await.unwrap();
    assert_ne!(native_subject, web_subject);
    let replacement = store
        .configure_issuer_client(&native(realm, id, "http://127.0.0.1:42005/other"))
        .await
        .unwrap();
    assert!(store.check_issuer_client(&current).await.is_err());
    assert_eq!(
        store.issuer_subject(&replacement, owner).await.unwrap(),
        native_subject
    );
    for query in [
        "UPDATE auth_issuer_clients SET redirect_profile='unrecognized'",
        "UPDATE auth_issuer_clients SET redirect_profile='web_exact'",
        "UPDATE auth_issuer_clients SET sector='unrelated.example'",
        "UPDATE auth_issuer_clients SET authentication='client_secret_basic', secret_verifier=decode(repeat('00',32),'hex')",
    ] {
        assert!(sqlx::raw_sql(query).execute(&pool).await.is_err());
    }
    store.check_issuer_client(&replacement).await.unwrap();
}

#[sqlx::test]
async fn failed_native_replacement_rolls_back_profile_sector_and_existing_definition(pool: PgPool) {
    let (store, realm, owner) = setup(&pool).await;
    let id = Uuid::new_v4();
    let web = store
        .configure_issuer_client(&public(realm, id, "https://app.example/cb"))
        .await
        .unwrap();
    let subject = store.issuer_subject(&web, owner).await.unwrap();
    sqlx::raw_sql("ALTER TABLE auth_issuer_clients ADD CONSTRAINT owned_native_fault CHECK (redirect_profile='web_exact') NOT VALID").execute(&pool).await.unwrap();
    assert!(matches!(
        store
            .configure_issuer_client(&native(realm, id, "http://127.0.0.1/cb"))
            .await,
        Err(Error::Unavailable)
    ));
    store.check_issuer_client(&web).await.unwrap();
    assert_eq!(store.issuer_subject(&web, owner).await.unwrap(), subject);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM auth_issuer_sectors")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
}
