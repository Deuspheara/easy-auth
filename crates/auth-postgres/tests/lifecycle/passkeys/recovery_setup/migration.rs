use super::*;

#[sqlx::test(migrations = false)]
async fn recovery_setup_upgrade_preserves_accounts_without_inventing_saved_codes(pool: PgPool) {
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|m| m.version < 13)
    {
        sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
    }
    let (_, realm) = crate::support::realm(pool.clone()).await;
    let user = Uuid::new_v4();
    let other = Uuid::new_v4();
    let session = Uuid::new_v4();
    sqlx::query("INSERT INTO auth_users(realm_id,id,email) VALUES ($1,$2,'existing@example.test'),($1,$3,'other@example.test')")
        .bind(realm).bind(user).bind(other).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO auth_sessions(realm_id,id,user_id,token_hash,authentication_method) VALUES ($1,$2,$3,$4,'email')")
        .bind(realm).bind(session).bind(user).bind(Secret::generate().unwrap().verifier().as_slice()).execute(&pool).await.unwrap();
    let before: String = sqlx::query_scalar(
        "SELECT row_to_json(t)::text FROM auth_sessions t WHERE realm_id=$1 AND id=$2",
    )
    .bind(realm)
    .bind(session)
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::raw_sql(include_str!(
        "../../../../migrations/0013_passkey_recovery_setup.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let after: String = sqlx::query_scalar(
        "SELECT row_to_json(t)::text FROM auth_sessions t WHERE realm_id=$1 AND id=$2",
    )
    .bind(realm)
    .bind(session)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(before == after);
    let counts: (i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_passkey_recovery_codes),(SELECT count(*) FROM auth_passkey_recovery_setups)")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(counts, (0, 0));
    assert!(sqlx::query("INSERT INTO auth_passkey_recovery_setups(realm_id,user_id,rp_id,id,session_id,code_hash) VALUES ($1,$2,'login.example.com',$3,$4,$5)")
        .bind(realm).bind(other).bind(Uuid::new_v4()).bind(session).bind([2u8;32].as_slice()).execute(&pool).await.is_err(), "cross-owner session FK");
    assert!(sqlx::query("INSERT INTO auth_passkey_recovery_codes(realm_id,user_id,rp_id,version,code_hash) VALUES ($1,$2,'login.example.com',$3,decode('01','hex'))")
        .bind(realm).bind(user).bind(Uuid::new_v4()).execute(&pool).await.is_err(), "malformed verifier rejected");
    assert!(sqlx::query("INSERT INTO auth_audit(realm_id,user_id,kind,schema_version) VALUES ($1,$2,'passkey_recovery_configured',1)")
        .bind(realm).bind(user).execute(&pool).await.is_err(), "actor provenance required");
}
