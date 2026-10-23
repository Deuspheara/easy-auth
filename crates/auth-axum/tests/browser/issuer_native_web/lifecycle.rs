use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn native_code_and_rotation_emit_only_committed_profile_credentials_and_one_admission(
    pool: PgPool,
) {
    let f = fixture(pool).await;
    let initial = issued(&f).await;
    assert_eq!(initial.as_object().unwrap().len(), 7);
    assert_eq!(initial["scope"], ISSUER_NATIVE_SCOPE);
    assert!(initial["id_token"].is_string());
    assert_eq!(f.facts().await, (1, 1, 1, 1));
    assert_eq!(f.base.facts().await, (1, 1, 1));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT sum(attempts)::bigint FROM auth_issuer_token_admission WHERE realm_id=$1"
        )
        .bind(f.base.realm)
        .fetch_one(&f.base.pool)
        .await
        .unwrap(),
        1
    );
    let before:(i64,i64,i64)=sqlx::query_as("SELECT (extract(epoch FROM authenticated_at)*1000000)::bigint,(extract(epoch FROM last_seen_at)*1000000)::bigint,(extract(epoch FROM expires_at)*1000000)::bigint FROM auth_sessions WHERE realm_id=$1").bind(f.base.realm).fetch_one(&f.base.pool).await.unwrap();
    let response = refresh(&f, initial["refresh_token"].as_str().unwrap()).await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    let next = read(response).await;
    assert_eq!(next.as_object().unwrap().len(), 6);
    assert!(next.get("id_token").is_none());
    assert_ne!(next["refresh_token"], initial["refresh_token"]);
    assert!(next["expires_in"].as_u64().unwrap() <= 300);
    assert_eq!(next["scope"], ISSUER_NATIVE_SCOPE);
    let after:(i64,i64,i64)=sqlx::query_as("SELECT (extract(epoch FROM authenticated_at)*1000000)::bigint,(extract(epoch FROM last_seen_at)*1000000)::bigint,(extract(epoch FROM expires_at)*1000000)::bigint FROM auth_sessions WHERE realm_id=$1").bind(f.base.realm).fetch_one(&f.base.pool).await.unwrap();
    assert_eq!(before, after);
    assert_eq!(f.base.facts().await, (1, 1, 2));
    let response = refresh(&f, initial["refresh_token"].as_str().unwrap()).await;
    assert_eq!(response.status(), 400);
    assert_eq!(read(response).await, json!({"error":"invalid_grant"}));
    assert_eq!(
        refresh(&f, next["refresh_token"].as_str().unwrap())
            .await
            .status(),
        400
    );
    assert!(sqlx::query_scalar::<_,bool>("SELECT bool_and(revoked_at_us IS NOT NULL) FROM auth_issuer_access_tokens WHERE realm_id=$1").bind(f.base.realm).fetch_one(&f.base.pool).await.unwrap());
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn actual_online_public_and_confidential_clients_retain_code_only_wire_behavior(
    pool: PgPool,
) {
    for profile in [
        crate::support::issuer_web::Profile::Public,
        crate::support::issuer_web::Profile::Confidential,
    ] {
        let mut f = crate::support::issuer_web::Fixture::new(pool.clone(), profile).await;
        let authority = IssuerAuthority::new(f.realm, ORIGIN).unwrap();
        let base = IssuerWebServices::new(
            authority,
            f.store.clone(),
            f.store.clone(),
            vec![f.key.clone()],
        )
        .unwrap();
        let services =
            IssuerNativeWebServices::new(base, f.store.clone(), f.store.clone(), f.store.clone());
        f.app = experimental_issuer_native_web_router(
            Auth::new(
                f.realm,
                f.store.clone(),
                Arc::new(crate::support::Mail::default()),
            ),
            BrowserConfig::new(ORIGIN, false).unwrap(),
            services,
        )
        .unwrap();
        let code = f.code().await;
        let response = f.send(f.body(&code), f.basic().as_deref()).await;
        assert_eq!(response.status(), 200);
        let tokens = read(response).await;
        assert_eq!(tokens.as_object().unwrap().len(), 5);
        assert!(tokens.get("refresh_token").is_none());
        assert_eq!(tokens["scope"], "openid");
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT sum(attempts)::bigint FROM auth_issuer_token_admission WHERE realm_id=$1"
            )
            .bind(f.realm)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
            1
        );
        let body = status_body(f.client.client(), tokens["access_token"].as_str().unwrap());
        let response = f
            .app
            .clone()
            .oneshot(token_request(
                "/oidc/revoke",
                body,
                f.basic().as_deref(),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert!(
            sqlx::query_scalar::<_, bool>(
                "SELECT revoked_at_us IS NOT NULL FROM auth_issuer_access_tokens WHERE realm_id=$1"
            )
            .bind(f.realm)
            .fetch_one(&f.pool)
            .await
            .unwrap()
        );
    }
}
