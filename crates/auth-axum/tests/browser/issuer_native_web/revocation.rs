use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn native_wire_revoke_can_only_reduce_its_family_after_policy_disable(pool: PgPool) {
    let f = fixture(pool).await;
    let initial = issued(&f).await;
    let next = read(refresh(&f, initial["refresh_token"].as_str().unwrap()).await).await;
    f.base
        .store
        .disable_issuer_native_refresh_policy(f.policy.authority(), f.base.client.client())
        .await
        .unwrap();
    assert_eq!(
        revoke(&f, initial["access_token"].as_str().unwrap())
            .await
            .status(),
        200
    );
    assert_eq!(
        revoke(&f, next["refresh_token"].as_str().unwrap())
            .await
            .status(),
        200
    );
    assert_eq!(revoke(&f, "unknown-opaque-value").await.status(), 200);
    assert_eq!(
        refresh(&f, next["refresh_token"].as_str().unwrap())
            .await
            .status(),
        400
    );
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT revoked_at_us IS NOT NULL FROM auth_issuer_native_families WHERE realm_id=$1"
        )
        .bind(f.base.realm)
        .fetch_one(&f.base.pool)
        .await
        .unwrap()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='issuer_native_revoked'"
        )
        .bind(f.base.realm)
        .fetch_one(&f.base.pool)
        .await
        .unwrap(),
        1
    );
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn completed_signature_then_http_refresh_revoke_race_leaves_no_live_descendant(pool: PgPool) {
    let f = fixture(pool).await;
    let initial = issued(&f).await;
    let token = initial["refresh_token"].as_str().unwrap();
    // Signature completed before these database-only credential operations.
    let (rotated, revoked) = tokio::join!(refresh(&f, token), revoke(&f, token));
    assert_eq!(revoked.status(), 200);
    assert!(rotated.status() == 200 || rotated.status() == 400);
    assert_eq!(refresh(&f, token).await.status(), 400);
    assert!(sqlx::query_scalar::<_,bool>("SELECT bool_and(revoked_at_us IS NOT NULL) FROM auth_issuer_access_tokens WHERE realm_id=$1").bind(f.base.realm).fetch_one(&f.base.pool).await.unwrap());
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn native_refresh_http_audit_fault_retains_original_credential_for_atomic_retry(
    pool: PgPool,
) {
    let f = fixture(pool).await;
    let initial = issued(&f).await;
    let token = initial["refresh_token"].as_str().unwrap();
    sqlx::raw_sql("ALTER TABLE auth_audit ADD CONSTRAINT owned_wire_refresh_fault CHECK(kind<>'issuer_native_rotated') NOT VALID").execute(&f.base.pool).await.unwrap();
    let response = refresh(&f, token).await;
    assert_eq!(response.status(), 503);
    assert_eq!(
        read(response).await,
        json!({"error":"temporarily_unavailable"})
    );
    assert_eq!(f.base.facts().await, (1, 1, 1));
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT generation=0 FROM auth_issuer_native_families WHERE realm_id=$1"
        )
        .bind(f.base.realm)
        .fetch_one(&f.base.pool)
        .await
        .unwrap()
    );
    sqlx::raw_sql("ALTER TABLE auth_audit DROP CONSTRAINT owned_wire_refresh_fault")
        .execute(&f.base.pool)
        .await
        .unwrap();
    assert_eq!(refresh(&f, token).await.status(), 200);
    assert_eq!(f.base.facts().await, (1, 1, 2));
}
