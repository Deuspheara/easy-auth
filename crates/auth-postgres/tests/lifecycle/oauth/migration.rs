use crate::support::{realm, signed_in};
use auth_core::{OAuthIntent, OAuthPurpose, OAuthTransactions, Repository, Secret};
use sqlx::PgPool;
use std::sync::Arc;

#[sqlx::test(migrations = false)]
async fn migration_preserves_existing_identity_session_and_audit(pool: PgPool) {
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|m| m.version <= 15)
    {
        sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
    }
    let (store, realm) = realm(pool.clone()).await;
    let session = signed_in(&store, realm, "upgrade@example.test").await;
    let user = store
        .authenticate(realm, session.verifier())
        .await
        .unwrap()
        .id;
    let before:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_audit)")
        .fetch_one(&pool).await.unwrap();
    sqlx::raw_sql(include_str!(
        "../../../migrations/0016_oauth_transactions.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        store
            .authenticate(realm, session.verifier())
            .await
            .unwrap()
            .id,
        user
    );
    let after:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_audit)")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(before, after);
    crate::support::schema::finish_upgrade_after(&pool, 16).await;
    let connection = super::setup::connection(realm, uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    let connection = store.configure_oauth_connection(&connection).await.unwrap();
    let flow = OAuthTransactions::new(connection, Arc::new(store));
    let browser = Secret::generate().unwrap();
    flow.begin(&OAuthIntent {
        browser: &browser,
        source: "192.0.2.22",
        purpose: OAuthPurpose::SignIn,
    })
    .await
    .unwrap();
}
