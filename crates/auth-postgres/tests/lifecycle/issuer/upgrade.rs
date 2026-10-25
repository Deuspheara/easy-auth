use super::*;

#[sqlx::test(migrations = false)]
async fn issuer_migration_preserves_existing_account_and_session_rows(pool: PgPool) {
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|m| m.version <= 26)
    {
        sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
    }
    let (store, realm, user) = setup(&pool).await;
    let before: serde_json::Value =
        sqlx::query_scalar("SELECT to_jsonb(u) FROM auth_users u WHERE realm_id=$1 AND id=$2")
            .bind(realm)
            .bind(user)
            .fetch_one(&pool)
            .await
            .unwrap();
    let sessions: serde_json::Value = sqlx::query_scalar(
        "SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM auth_sessions s WHERE realm_id=$1",
    )
    .bind(realm)
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::raw_sql(include_str!("../../../migrations/0027_issuer_clients.sql"))
        .execute(&pool)
        .await
        .unwrap();
    let after: serde_json::Value =
        sqlx::query_scalar("SELECT to_jsonb(u) FROM auth_users u WHERE realm_id=$1 AND id=$2")
            .bind(realm)
            .bind(user)
            .fetch_one(&pool)
            .await
            .unwrap();
    let after_sessions: serde_json::Value = sqlx::query_scalar(
        "SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM auth_sessions s WHERE realm_id=$1",
    )
    .bind(realm)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(before, after);
    assert_eq!(sessions, after_sessions);
    // Finish later additive schema before using today's adapter; retain the
    // historical 0027 account/session assertions above unchanged.
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|m| m.version > 27)
    {
        sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
    }
    let c = store
        .configure_issuer_client(&public(realm, Uuid::new_v4(), "https://app.example/cb"))
        .await
        .unwrap();
    assert_ne!(store.issuer_subject(&c, user).await.unwrap(), user);
}
