use super::*;
use http_body_util::BodyExt;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn actual_code_issuance_basic_introspection_and_idempotent_revocation_need_no_cookies_or_origin(
    pool: PgPool,
) {
    let f = fixture(pool, Profile::Confidential).await;
    let token = issued(&f).await;
    let response = send(&f, "/oidc/introspect", body(&f, token.expose())).await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    let active = read(response).await;
    let mut names = active
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "active",
            "aud",
            "client_id",
            "exp",
            "iat",
            "iss",
            "scope",
            "sub",
            "token_type"
        ]
    );
    assert_eq!(active["active"], true);
    assert_eq!(active["iss"], ORIGIN);
    assert_eq!(active["aud"], f.client.client().to_string());
    assert_eq!(active["client_id"], f.client.client().to_string());
    assert_eq!(active["scope"], "openid");
    assert_eq!(active["token_type"], "Bearer");
    assert!(active["exp"].as_i64().unwrap() > active["iat"].as_i64().unwrap());
    let response = send(&f, "/oidc/introspect", body(&f, "foreign-opaque-format")).await;
    assert_eq!(response.status(), 200);
    assert!(read(response).await == json!({"active":false}));
    for presented in [token.expose(), token.expose(), "unknown-opaque-token"] {
        let response = send(&f, "/oidc/revoke", body(&f, presented)).await;
        assert_eq!(response.status(), 200);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
        assert!(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
    }
    let response = send(&f, "/oidc/introspect", body(&f, token.expose())).await;
    assert_eq!(response.status(), 200);
    assert!(read(response).await == json!({"active":false}));
    assert_eq!(f.facts().await, (1, 1, 1));
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn public_identification_or_actual_local_cookie_cannot_authenticate_introspection_but_possession_can_revoke(
    pool: PgPool,
) {
    let f = fixture(pool, Profile::Public).await;
    let token = issued(&f).await;
    let mut request = token_request("/oidc/introspect", body(&f, token.expose()), None, true);
    request
        .headers_mut()
        .insert(header::COOKIE, f.current.parse().unwrap());
    let response = f.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), 401);
    assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
    assert!(read(response).await == json!({"error":"invalid_client"}));
    let response = send(
        &f,
        "/oidc/revoke",
        body(&f, token.expose()) + "&token_type_hint=unknown",
    )
    .await;
    assert_eq!(response.status(), 200);
    let revoked: bool = sqlx::query_scalar(
        "SELECT revoked_at_us IS NOT NULL FROM auth_issuer_access_tokens WHERE realm_id=$1",
    )
    .bind(f.realm)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(revoked);
    let mut current = get("/v1/session");
    current
        .headers_mut()
        .insert(header::COOKIE, f.current.parse().unwrap());
    assert_eq!(f.app.clone().oneshot(current).await.unwrap().status(), 200);
    let mut bearer = get("/v1/session");
    bearer.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Bearer {}", token.expose()).parse().unwrap(),
    );
    assert_eq!(f.app.clone().oneshot(bearer).await.unwrap().status(), 401);
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn management_routes_contract_and_authority_are_explicit_and_storage_failure_is_not_inactive(
    pool: PgPool,
) {
    let f = fixture(pool, Profile::Confidential).await;
    let contract = serde_json::to_value(easy_auth_axum::issuer_token_management_openapi()).unwrap();
    assert!(contract["paths"].get("/oidc/token").is_some());
    for path in ["/oidc/revoke", "/oidc/introspect"] {
        assert!(contract["paths"].get(path).is_some());
    }
    assert_eq!(
        contract["components"]["schemas"]["TokenStatusInput"]["additionalProperties"],
        false
    );
    for name in ["ActiveToken", "InactiveToken"] {
        assert_eq!(
            contract["components"]["schemas"][name]["additionalProperties"],
            false
        );
    }
    let authority = IssuerAuthority::new(f.realm, ORIGIN).unwrap();
    let base = easy_auth_axum::experimental_issuer_web_router(
        Auth::new(f.realm, f.store.clone(), Arc::new(Mail::default())),
        BrowserConfig::new(ORIGIN, false).unwrap(),
        IssuerWebServices::new(
            authority.clone(),
            f.store.clone(),
            f.store.clone(),
            vec![f.key.clone()],
        )
        .unwrap(),
    )
    .unwrap();
    for path in ["/oidc/revoke", "/oidc/introspect"] {
        assert_eq!(
            base.clone()
                .oneshot(token_request(
                    path,
                    body(&f, "unknown"),
                    f.basic().as_deref(),
                    true
                ))
                .await
                .unwrap()
                .status(),
            404
        );
    }
    let foreign = Arc::new(IssuerTokenManagement::new(
        IssuerAuthority::new(Uuid::new_v4(), ORIGIN).unwrap(),
        f.store.clone(),
    ));
    assert!(
        experimental_issuer_token_management_web_router(
            Auth::new(f.realm, f.store.clone(), Arc::new(Mail::default())),
            BrowserConfig::new(ORIGIN, false).unwrap(),
            IssuerWebServices::new(
                authority,
                f.store.clone(),
                f.store.clone(),
                vec![f.key.clone()]
            )
            .unwrap(),
            foreign
        )
        .is_err()
    );
    sqlx::query("ALTER TABLE auth_issuer_access_tokens RENAME TO test_unavailable_status")
        .execute(&f.pool)
        .await
        .unwrap();
    for path in ["/oidc/revoke", "/oidc/introspect"] {
        let response = send(&f, path, body(&f, "unknown-opaque-token")).await;
        assert_eq!(response.status(), 503);
        assert!(read(response).await == json!({"error":"temporarily_unavailable"}));
    }
}
