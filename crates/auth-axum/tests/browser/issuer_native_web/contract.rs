use super::*;
#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn explicit_native_metadata_and_closed_wire_contract_match_capabilities_without_changing_default(
    pool: PgPool,
) {
    let f = fixture(pool).await;
    let response = f
        .base
        .app
        .clone()
        .oneshot(get("/.well-known/openid-configuration"))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let metadata = read(response).await;
    assert_eq!(
        metadata["grant_types_supported"],
        json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(
        metadata["scopes_supported"],
        json!(["openid", "offline_access"])
    );
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("scope", ISSUER_NATIVE_SCOPE)
        .append_pair("state", "opaque")
        .finish();
    let response = f
        .base
        .app
        .clone()
        .oneshot(get(&format!("/oidc/authorize?{query}")))
        .await
        .unwrap();
    assert_eq!(response.status(), 302);
    assert_eq!(
        response.headers()[header::LOCATION],
        format!("/oidc/native/authorize?{query}")
    );
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    assert_eq!(f.facts().await, (0, 0, 0, 0));
    let api = read(
        f.base
            .app
            .clone()
            .oneshot(get("/openapi.json"))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        api,
        serde_json::to_value(easy_auth_axum::issuer_native_web_openapi()).unwrap()
    );
    for name in [
        "TokenResponse",
        "NativeCodeTokens",
        "NativeRefreshTokens",
        "RefreshForm",
    ] {
        assert_eq!(
            api["components"]["schemas"][name]["additionalProperties"],
            false
        );
    }
    for path in [
        "/oidc/token",
        "/oidc/revoke",
        "/oidc/introspect",
        "/v1/oidc/native/consent/approve",
    ] {
        assert!(api["paths"].get(path).is_some());
    }
    let services = IssuerWebServices::new(
        f.policy.authority().clone(),
        f.base.store.clone(),
        f.base.store.clone(),
        vec![f.base.key.clone()],
    )
    .unwrap();
    let default = easy_auth_axum::experimental_issuer_web_router(
        Auth::new(f.base.realm, f.base.store.clone(), f.mail.clone()),
        BrowserConfig::new(ORIGIN, false).unwrap(),
        services,
    )
    .unwrap();
    let metadata = read(
        default
            .oneshot(get("/.well-known/openid-configuration"))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        metadata["grant_types_supported"],
        json!(["authorization_code"])
    );
    assert_eq!(metadata["scopes_supported"], json!(["openid"]));
}
