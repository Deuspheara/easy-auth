use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn native_http_audit_failure_does_not_report_approval_clear_proofs_or_consume_retry(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let (proofs, preview) = f.prepare().await;
    let decision = json!({"authorization":preview["authorization"]});
    sqlx::raw_sql("ALTER TABLE auth_audit ADD CONSTRAINT owned_http_approval_fault CHECK(kind<>'issuer_authorized') NOT VALID")
        .execute(&f.base.pool).await.unwrap();
    let response = f.send("approve", &decision, &proofs).await;
    assert_eq!(response.status(), 503);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    assert_eq!(f.facts().await, (1, 1, 0, 0));
    assert!(sqlx::query_scalar::<_,bool>("SELECT a.status='pending' AND a.code_hash IS NULL AND c.approved_at_us IS NULL FROM auth_issuer_authorizations a JOIN auth_issuer_native_consents c ON (c.realm_id,c.authorization_id)=(a.realm_id,a.id) WHERE a.realm_id=$1")
        .bind(f.base.realm).fetch_one(&f.base.pool).await.unwrap());
    sqlx::raw_sql("ALTER TABLE auth_audit DROP CONSTRAINT owned_http_approval_fault")
        .execute(&f.base.pool)
        .await
        .unwrap();
    assert_eq!(f.send("approve", &decision, &proofs).await.status(), 200);
    assert_eq!(f.facts().await, (1, 1, 0, 1));
}
