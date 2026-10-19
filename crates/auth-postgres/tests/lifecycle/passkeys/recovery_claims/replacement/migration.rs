use super::*;

#[sqlx::test(migrations = false)]
async fn replacement_schema_preserves_existing_claims_and_enforces_owned_private_stages(
    pool: PgPool,
) {
    for m in sqlx::migrate!("./migrations")
        .iter()
        .filter(|m| m.version < 15)
    {
        sqlx::raw_sql(&m.sql).execute(&pool).await.unwrap();
    }
    let (_, realm) = crate::support::realm(pool.clone()).await;
    let owner = Uuid::new_v4();
    let peer = Uuid::new_v4();
    let claim = Uuid::new_v4();
    let version = Uuid::new_v4();
    sqlx::query("INSERT INTO auth_users(realm_id,id,email) VALUES ($1,$2,'owner@example.test'),($1,$3,'peer@example.test')").bind(realm).bind(owner).bind(peer).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO auth_passkey_recovery_codes(realm_id,user_id,rp_id,version,code_hash,consumed_at) VALUES ($1,$2,'login.example.com',$3,$4,clock_timestamp())")
        .bind(realm).bind(owner).bind(version).bind([83u8;32].as_slice()).execute(&pool).await.unwrap();
    sqlx::query("WITH instant AS (SELECT clock_timestamp() AS now) INSERT INTO auth_passkey_recovery_claims(realm_id,user_id,rp_id,id,code_version,browser_hash,created_at,expires_at,delay_seconds,notification_required,not_before) SELECT $1,$2,'login.example.com',$3,$4,$5,now,now+interval '7 days',86400,false,now+interval '1 day' FROM instant")
        .bind(realm).bind(owner).bind(claim).bind(version).bind([84u8;32].as_slice()).execute(&pool).await.unwrap();
    let before: String = sqlx::query_scalar(
        "SELECT row_to_json(c)::text FROM auth_passkey_recovery_claims c WHERE realm_id=$1",
    )
    .bind(realm)
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::raw_sql(include_str!(
        "../../../../../migrations/0015_passkey_recovery_replacement.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let after: serde_json::Value = sqlx::query_scalar::<_, String>(
        "SELECT row_to_json(c)::text FROM auth_passkey_recovery_claims c WHERE realm_id=$1",
    )
    .bind(realm)
    .fetch_one(&pool)
    .await
    .unwrap()
    .parse()
    .unwrap();
    let mut expected: serde_json::Value = before.parse().unwrap();
    expected["completed_at"] = serde_json::Value::Null;
    assert_eq!(expected, after);
    assert!(sqlx::query("INSERT INTO auth_passkey_recovery_replacements(realm_id,claim_id,id,user_id,registration_state,expires_at) VALUES ($1,$2,$3,$4,$5,clock_timestamp()+interval '2 minutes')")
        .bind(realm).bind(claim).bind(Uuid::new_v4()).bind(peer).bind([1u8].as_slice()).execute(&pool).await.is_err(),"candidate must have claim's owner");
    assert!(sqlx::query("INSERT INTO auth_passkey_recovery_replacements(realm_id,claim_id,id,user_id,stage,registration_state,expires_at) VALUES ($1,$2,$3,$4,'assertion',$5,clock_timestamp()+interval '2 minutes')")
        .bind(realm).bind(claim).bind(Uuid::new_v4()).bind(owner).bind([1u8].as_slice()).execute(&pool).await.is_err(),"registration cannot masquerade as assertion stage");
    assert!(sqlx::query("INSERT INTO auth_audit(realm_id,user_id,kind,schema_version,recovery_claim_id) VALUES ($1,$2,'passkey_recovered',1,$3)")
        .bind(realm).bind(owner).bind(claim).execute(&pool).await.is_err(),"recovery fact requires issued session attribution");
}
