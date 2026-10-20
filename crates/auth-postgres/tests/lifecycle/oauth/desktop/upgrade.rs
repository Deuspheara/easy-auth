use crate::support::{legacy_oauth, realm, schema::finish_upgrade_after, signed_in};
use auth_core::*;
use serde_json::Value;
use sqlx::PgPool;
use std::sync::Arc;

#[sqlx::test(migrations = false)]
async fn desktop_return_upgrade_preserves_legacy_caps_proofs_sessions_and_exact_policy(
    pool: PgPool,
) {
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|m| m.version <= 19)
    {
        sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
    }
    let (store, realm) = realm(pool.clone()).await;
    let store = Arc::new(store);
    let current = signed_in(&store, realm, "desktop-upgrade@example.test").await;
    let owner = store.authenticate(realm, current.verifier()).await.unwrap();
    let c = legacy_oauth::connection(&pool, realm).await;
    let browser = Secret::generate().unwrap();
    let start = legacy_oauth::pending(&pool, &c, &browser).await;
    let before: (Value, Value) = sqlx::query_as("SELECT to_jsonb(c),to_jsonb(t) FROM auth_oauth_connections c JOIN auth_oauth_transactions t ON t.realm_id=c.realm_id AND t.connection_id=c.id AND t.client_id=c.client_id WHERE c.realm_id=$1")
        .bind(realm).fetch_one(&pool).await.unwrap();
    finish_upgrade_after(&pool, 19).await;
    let after: (Value, Value) = sqlx::query_as("SELECT to_jsonb(c),to_jsonb(t) FROM auth_oauth_connections c JOIN auth_oauth_transactions t ON t.realm_id=c.realm_id AND t.connection_id=c.id AND t.client_id=c.client_id WHERE c.realm_id=$1")
        .bind(realm).fetch_one(&pool).await.unwrap();
    let (mut definition, mut transaction) = after;
    assert!(
        definition
            .as_object_mut()
            .unwrap()
            .remove("redirect_policy")
            == Some(Value::String("exact".into()))
    );
    assert!(
        transaction.as_object_mut().unwrap().remove("redirect_uri")
            == Some(Value::String(c.redirect().into()))
    );
    assert!(
        before == (definition, transaction),
        "original metadata/proof hashes/bindings/caps survive exactly"
    );
    assert_eq!(
        store.authenticate(realm, current.verifier()).await.unwrap(),
        owner
    );
    let flow = OAuthTransactions::new(c.clone(), store.clone());
    let intent = OAuthIntent {
        browser: &browser,
        source: "legacy-upgrade",
        purpose: OAuthPurpose::SignIn,
    };
    assert!(matches!(
        flow.consume(
            &intent,
            &start.state,
            super::super::setup::copy_proof(&start.proof),
            OAuthCallback {
                redirect: "http://127.0.0.1:49154/callback",
                issuer: Some(c.issuer())
            }
        )
        .await,
        Err(Error::Unauthorized)
    ));
    let exchange = flow
        .consume(
            &intent,
            &start.state,
            start.proof,
            OAuthCallback {
                redirect: c.redirect(),
                issuer: Some(c.issuer()),
            },
        )
        .await
        .unwrap();
    assert_eq!(exchange.configuration(), &c);
    assert_eq!(exchange.redirect(), c.redirect());
    let facts: (i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_audit),(SELECT count(*) FROM auth_oauth_transactions)")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(
        facts,
        (1, 1, 1, 0),
        "migrated consumption grants no identity or session"
    );
}
