use super::*;
use auth_core::Error;

#[sqlx::test]
async fn offline_profile_without_compiled_support_fails_closed_without_rewriting_registration(
    pool: PgPool,
) {
    let (store, realm, _) = setup(&pool).await;
    let client = store
        .configure_issuer_client(&native(realm, Uuid::new_v4(), "http://127.0.0.1/cb"))
        .await
        .unwrap();
    // Stored by a newer feature-enabled binary. This consumer must not silently
    // interpret the offline registration as an older online native client.
    sqlx::query("UPDATE auth_issuer_clients SET redirect_profile='native_refresh_loopback' WHERE realm_id=$1 AND id=$2")
        .bind(realm).bind(client.client()).execute(&pool).await.unwrap();
    assert!(matches!(
        store.load_issuer_client(realm, client.client()).await,
        Err(Error::Unavailable)
    ));
    assert!(store.check_issuer_client(&client).await.is_err());
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT redirect_profile FROM auth_issuer_clients WHERE realm_id=$1 AND id=$2"
        )
        .bind(realm)
        .bind(client.client())
        .fetch_one(&pool)
        .await
        .unwrap(),
        "native_refresh_loopback"
    );
}
