use super::*;

#[sqlx::test(migrations = false)]
async fn management_upgrade_preserves_existing_key_and_session_without_inventing_proof(
    pool: PgPool,
) {
    // Apply the published predecessor schema, then seed only its documented columns.
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|m| m.version < 12)
    {
        sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
    }
    let (store, realm) = crate::support::realm(pool.clone()).await;
    let user = Uuid::new_v4();
    let key = Uuid::new_v4();
    sqlx::query("INSERT INTO auth_users(realm_id,id,email) VALUES ($1,$2,'upgrade@example.test')")
        .bind(realm)
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO auth_passkeys(realm_id,id,user_id,rp_id,credential_id,credential,label) VALUES ($1,$2,$3,'login.example.com',decode('01','hex'),decode('0203','hex'),'Existing key')")
        .bind(realm).bind(key).bind(user).execute(&pool).await.unwrap();
    let current = Secret::generate().unwrap();
    sqlx::query("INSERT INTO auth_sessions(realm_id,id,user_id,token_hash,authentication_method) VALUES ($1,$2,$3,$4,'email')")
        .bind(realm).bind(Uuid::new_v4()).bind(user).bind(current.verifier().as_slice()).execute(&pool).await.unwrap();
    let before: (Vec<u8>, Vec<u8>, String) =
        sqlx::query_as("SELECT credential_id,credential,label FROM auth_passkeys WHERE id=$1")
            .bind(key)
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::raw_sql(include_str!(
        "../../../../migrations/0012_passkey_management.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let after: (Vec<u8>, Vec<u8>, String) =
        sqlx::query_as("SELECT credential_id,credential,label FROM auth_passkeys WHERE id=$1")
            .bind(key)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        before == after,
        "upgrade preserves credential encoding and label"
    );
    let (version, used): (Uuid, bool) = sqlx::query_as(
        "SELECT management_version,last_used_at IS NOT NULL FROM auth_passkeys WHERE id=$1",
    )
    .bind(key)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!version.is_nil());
    assert!(!used, "upgrade must not fabricate a private-key proof");
    assert_eq!(
        store
            .authenticate(realm, current.verifier())
            .await
            .unwrap()
            .id,
        user
    );
    assert!(sqlx::query("INSERT INTO auth_audit(realm_id,user_id,kind,schema_version) VALUES ($1,$2,'passkey_removed',1)")
        .bind(realm).bind(user).execute(&pool).await.is_err());
}
