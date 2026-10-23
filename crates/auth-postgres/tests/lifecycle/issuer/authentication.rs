use super::*;
use auth_core::{Error, IssuerClientAuthentication, Secret};

#[sqlx::test]
async fn stored_verifier_cannot_be_used_as_a_presented_client_secret(pool: PgPool) {
    let (store, realm, _) = setup(&pool).await;
    let secret = Secret::generate().unwrap();
    let client = store
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
    // Use the actual stored digest with ordinary database Base64url encoding,
    // not a forged proof or alternate hashing implementation. Never print it.
    let encoded: String = sqlx::query_scalar("SELECT rtrim(translate(encode(secret_verifier,'base64'),'+/','-_'),'=') FROM auth_issuer_clients WHERE realm_id=$1 AND id=$2")
        .bind(realm).bind(client.client()).fetch_one(&pool).await.unwrap();
    let digest_as_secret = Secret::parse(encoded).unwrap();
    let wrong = IssuerClientAuthentication::basic(client.client(), &digest_as_secret).unwrap();
    assert!(matches!(
        store
            .validate_issuer_client_authentication(&client, &wrong)
            .await,
        Err(Error::Unauthorized)
    ));
    let correct = IssuerClientAuthentication::basic(client.client(), &secret).unwrap();
    store
        .validate_issuer_client_authentication(&client, &correct)
        .await
        .unwrap();
}

#[sqlx::test]
async fn authentication_requires_the_exact_current_method_client_and_secret_without_grants(
    pool: PgPool,
) {
    let (store, realm, _) = setup(&pool).await;
    let secret = Secret::generate().unwrap();
    let id = Uuid::new_v4();
    let client = store
        .configure_issuer_client(
            &IssuerClientRegistration::confidential(
                realm,
                id,
                &["https://app.example/cb"],
                &secret,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let good = IssuerClientAuthentication::basic(id, &secret).unwrap();
    let before: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_audit)").fetch_one(&pool).await.unwrap();
    for wrong in [
        IssuerClientAuthentication::public(id).unwrap(),
        IssuerClientAuthentication::basic(Uuid::new_v4(), &secret).unwrap(),
        IssuerClientAuthentication::basic(id, &Secret::generate().unwrap()).unwrap(),
    ] {
        assert!(matches!(
            store
                .validate_issuer_client_authentication(&client, &wrong)
                .await,
            Err(Error::Unauthorized)
        ));
    }
    store
        .validate_issuer_client_authentication(&client, &good)
        .await
        .unwrap();
    let public = store
        .configure_issuer_client(&public(realm, Uuid::new_v4(), "https://app.example/public"))
        .await
        .unwrap();
    assert!(matches!(
        store
            .validate_issuer_client_authentication(
                &public,
                &IssuerClientAuthentication::basic(public.client(), &secret).unwrap()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    store
        .validate_issuer_client_authentication(
            &public,
            &IssuerClientAuthentication::public(public.client()).unwrap(),
        )
        .await
        .unwrap();
    let after: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_audit)").fetch_one(&pool).await.unwrap();
    assert_eq!(before, after);
}

#[sqlx::test]
async fn authentication_cannot_cross_realms_or_survive_credential_rotation_and_disable(
    pool: PgPool,
) {
    let (store, realm, _) = setup(&pool).await;
    let (_, other_realm, _) = setup(&pool).await;
    let id = Uuid::new_v4();
    let first = Secret::generate().unwrap();
    let next = Secret::generate().unwrap();
    let registration = |realm, secret: &Secret| {
        IssuerClientRegistration::confidential(realm, id, &["https://app.example/cb"], secret)
            .unwrap()
    };
    let a = store
        .configure_issuer_client(&registration(realm, &first))
        .await
        .unwrap();
    let b = store
        .configure_issuer_client(&registration(other_realm, &next))
        .await
        .unwrap();
    let old = IssuerClientAuthentication::basic(id, &first).unwrap();
    let rotated = IssuerClientAuthentication::basic(id, &next).unwrap();
    assert!(matches!(
        store.validate_issuer_client_authentication(&b, &old).await,
        Err(Error::Unauthorized)
    ));
    store
        .validate_issuer_client_authentication(&b, &rotated)
        .await
        .unwrap();
    let current = store
        .configure_issuer_client(&registration(realm, &next))
        .await
        .unwrap();
    assert!(matches!(
        store.validate_issuer_client_authentication(&a, &old).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        store
            .validate_issuer_client_authentication(&current, &old)
            .await,
        Err(Error::Unauthorized)
    ));
    store
        .validate_issuer_client_authentication(&current, &rotated)
        .await
        .unwrap();
    store.disable_issuer_client(realm, id).await.unwrap();
    assert!(matches!(
        store
            .validate_issuer_client_authentication(&current, &rotated)
            .await,
        Err(Error::Unauthorized)
    ));
    store
        .validate_issuer_client_authentication(&b, &rotated)
        .await
        .unwrap();
}

#[sqlx::test]
async fn authentication_storage_failure_is_unavailable_and_can_never_become_public_fallback(
    pool: PgPool,
) {
    let (store, realm, _) = setup(&pool).await;
    let client = store
        .configure_issuer_client(&public(realm, Uuid::new_v4(), "https://app.example/cb"))
        .await
        .unwrap();
    let authentication = IssuerClientAuthentication::public(client.client()).unwrap();
    sqlx::raw_sql("ALTER TABLE auth_issuer_clients RENAME TO owned_unavailable_issuer_clients")
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        store
            .validate_issuer_client_authentication(&client, &authentication)
            .await,
        Err(Error::Unavailable)
    ));
    sqlx::raw_sql("ALTER TABLE owned_unavailable_issuer_clients RENAME TO auth_issuer_clients")
        .execute(&pool)
        .await
        .unwrap();
    store
        .validate_issuer_client_authentication(&client, &authentication)
        .await
        .unwrap();
}
