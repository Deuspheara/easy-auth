use super::*;

#[sqlx::test(migrations = "./migrations")]
async fn retained_passkey_recovery_code_cannot_bypass_provider_required_policy(pool: PgPool) {
    let f = Claims::new(pool.clone(), true).await;
    sqlx::query("UPDATE auth_users SET authentication_policy='provider_required' WHERE realm_id=$1 AND id=$2").bind(f.f.realm).bind(f.owner).execute(&pool).await.unwrap();
    let result = f.flow.begin(f.owner, &f.code, &f.browser, SOURCE).await;
    assert!(matches!(result, Err(Error::Unauthorized)));
    let facts: (i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_passkey_recovery_claims),(SELECT count(*) FROM auth_passkey_recovery_codes WHERE consumed_at IS NULL)").fetch_one(&pool).await.unwrap();
    assert_eq!(
        facts,
        (0, 1),
        "policy denial must not consume an old independent code or reserve a claim"
    );
}
