use super::*;

#[sqlx::test(migrations = false)]
async fn claim_upgrade_preserves_saved_codes_and_enforces_owned_notice_and_audit_bindings(
    pool: PgPool,
) {
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|m| m.version < 14)
    {
        sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
    }
    let (_, realm) = crate::support::realm(pool.clone()).await;
    let user = Uuid::new_v4();
    let peer = Uuid::new_v4();
    let version = Uuid::new_v4();
    sqlx::query("INSERT INTO auth_users(realm_id,id,email) VALUES ($1,$2,'owner@example.test'),($1,$3,'peer@example.test')")
        .bind(realm).bind(user).bind(peer).execute(&pool).await.unwrap();
    let code = Secret::generate().unwrap();
    sqlx::query("INSERT INTO auth_passkey_recovery_codes(realm_id,user_id,rp_id,version,code_hash) VALUES ($1,$2,'login.example.com',$3,$4)")
        .bind(realm).bind(user).bind(version).bind(code.verifier().as_slice()).execute(&pool).await.unwrap();
    sqlx::raw_sql(include_str!(
        "../../../../migrations/0014_passkey_recovery_claims.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let saved:(Uuid,Vec<u8>,bool)=sqlx::query_as("SELECT version,code_hash,consumed_at IS NULL FROM auth_passkey_recovery_codes WHERE realm_id=$1")
        .bind(realm).fetch_one(&pool).await.unwrap();
    assert!(saved.0 == version && saved.1 == code.verifier() && saved.2);
    let claim = Uuid::new_v4();
    sqlx::query("WITH instant AS (SELECT clock_timestamp() AS now) INSERT INTO auth_passkey_recovery_claims(realm_id,user_id,rp_id,id,code_version,browser_hash,created_at,expires_at,delay_seconds,notification_required) SELECT $1,$2,'login.example.com',$3,$4,$5,now,now+interval '7 days',86400,true FROM instant")
        .bind(realm).bind(user).bind(claim).bind(version).bind([1u8;32].as_slice()).execute(&pool).await.unwrap();
    assert!(sqlx::query("INSERT INTO auth_security_notifications(realm_id,id,user_id,recipient,kind,recovery_claim_id) VALUES ($1,$2,$3,'peer@example.test','passkey_recovery_started',$4)")
        .bind(realm).bind(Uuid::new_v4()).bind(peer).bind(claim).execute(&pool).await.is_err(),"cross-owner notification is rejected");
    assert!(sqlx::query("INSERT INTO auth_security_notifications(realm_id,id,user_id,recipient,kind) VALUES ($1,$2,$3,'owner@example.test','passkey_recovery_started')")
        .bind(realm).bind(Uuid::new_v4()).bind(user).execute(&pool).await.is_err(),"start notice needs a bound claim");
    assert!(
        sqlx::query(
            "UPDATE auth_passkey_recovery_claims SET not_before=clock_timestamp() WHERE realm_id=$1"
        )
        .bind(realm)
        .execute(&pool)
        .await
        .is_err(),
        "a receipt cannot be fabricated by an unpaired schedule value"
    );
    assert!(sqlx::query("INSERT INTO auth_audit(realm_id,user_id,kind,schema_version) VALUES ($1,$2,'passkey_recovery_started',1)")
        .bind(realm).bind(user).execute(&pool).await.is_err(),"typed recovery target is required");
}
