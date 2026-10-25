use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn resuming_requires_private_proofs_and_preserves_original_pending_lifetime_without_authority(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let pending = f.prepare().await;
    let original: (i64, i64) = sqlx::query_as(
        "SELECT created_at_us,expires_at_us FROM auth_issuer_authorizations WHERE realm_id=$1",
    )
    .bind(f.realm)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(
        f.send("/v1/oidc/consent/resume", json!({}), &f.current)
            .await
            .status(),
        401
    );
    assert_eq!(
        f.send(
            "/v1/oidc/consent/resume",
            json!({"authorization":pending.authorization}),
            &pending.cookies
        )
        .await
        .status(),
        400
    );
    let preview = f
        .send("/v1/oidc/consent/resume", json!({}), &pending.cookies)
        .await;
    assert_eq!(preview.status(), 200);
    assert!(!preview.headers().contains_key(header::SET_COOKIE));
    let public = read(preview).await;
    assert_eq!(public["authorization"], pending.authorization.to_string());
    assert_eq!(public["expires_at_us"], original.1);
    assert!(
        public.get("nonce").is_none()
            && public.get("state").is_none()
            && public.get("handle").is_none()
    );
    let after: (i64, i64) = sqlx::query_as(
        "SELECT created_at_us,expires_at_us FROM auth_issuer_authorizations WHERE realm_id=$1",
    )
    .bind(f.realm)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(original, after);
    assert_eq!(f.count("auth_issuer_subjects").await, 0);
    assert_eq!(f.count("auth_sessions").await, 1);
    assert_eq!(
        f.send(
            "/v1/oidc/consent/approve",
            Fixture::decision(&pending),
            &pending.cookies
        )
        .await
        .status(),
        200
    );
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn expired_resume_clears_unusable_transport_but_storage_failure_retains_retry_proofs(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let pending = f.prepare().await;
    sqlx::query("ALTER TABLE auth_issuer_authorizations RENAME TO unavailable_issuer_state")
        .execute(&f.pool)
        .await
        .unwrap();
    let failed = f
        .send("/v1/oidc/consent/resume", json!({}), &pending.cookies)
        .await;
    assert_eq!(failed.status(), 503);
    assert!(!failed.headers().contains_key(header::SET_COOKIE));
    sqlx::query("ALTER TABLE unavailable_issuer_state RENAME TO auth_issuer_authorizations")
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE auth_issuer_authorizations SET expires_at_us=created_at_us+1 WHERE realm_id=$1",
    )
    .bind(f.realm)
    .execute(&f.pool)
    .await
    .unwrap();
    let expired = f
        .send("/v1/oidc/consent/resume", json!({}), &pending.cookies)
        .await;
    assert_eq!(expired.status(), 401);
    for name in [
        "__Host-auth-issuer-browser=",
        "__Host-auth-issuer-handle=",
        "__Host-auth-issuer-operation=",
    ] {
        assert!(cookie(&expired, name).ends_with('='));
    }
    assert_eq!(f.count("auth_issuer_subjects").await, 0);
    f.prepare().await;
    assert_eq!(f.count("auth_issuer_authorizations").await, 1);
}
