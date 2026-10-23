use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn exact_discovery_and_public_jwks_are_opt_in_and_cannot_select_foreign_namespaces(
    pool: PgPool,
) {
    let f = Fixture::new(pool, Profile::Public).await;
    let response = f
        .app
        .clone()
        .oneshot(get("/.well-known/openid-configuration"))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    let doc = read(response).await;
    assert_eq!(doc["issuer"], ORIGIN);
    assert_eq!(doc["token_endpoint"], format!("{ORIGIN}/oidc/token"));
    assert_eq!(
        doc["authorization_endpoint"],
        format!("{ORIGIN}/oidc/authorize")
    );
    assert_eq!(doc["jwks_uri"], format!("{ORIGIN}/oidc/jwks"));
    assert_eq!(
        doc["id_token_signing_alg_values_supported"],
        json!(["RS256"])
    );
    assert_eq!(
        doc["token_endpoint_auth_methods_supported"],
        json!(["none", "client_secret_basic"])
    );
    assert_eq!(doc["request_uri_parameter_supported"], false);
    assert!(doc.get("userinfo_endpoint").is_none());
    let response = f.app.clone().oneshot(get("/oidc/jwks")).await.unwrap();
    assert_eq!(response.status(), 200);
    let jwks = read(response).await;
    let key = &jwks["keys"][0];
    let mut fields = key
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    fields.sort_unstable();
    assert_eq!(fields, ["alg", "e", "key_ops", "kid", "kty", "n", "use"]);
    assert_eq!(key["kid"], f.key.id().to_string());
    for path in [
        "/oidc/jwks?realm=other",
        "/.well-known/openid-configuration?issuer=other",
    ] {
        assert_eq!(
            f.app.clone().oneshot(get(path)).await.unwrap().status(),
            400
        );
    }
    let base = crate::support::app(f.pool.clone()).await.0;
    assert_eq!(
        base.oneshot(get("/.well-known/openid-configuration"))
            .await
            .unwrap()
            .status(),
        404
    );
    let contract = serde_json::to_value(easy_auth_axum::issuer_web_openapi()).unwrap();
    assert!(contract["paths"].get("/oidc/token").is_some());
    assert!(contract["paths"].get("/v1/oidc/consent/approve").is_some());
    assert_eq!(
        contract["components"]["schemas"]["TokenFormSchema"]["additionalProperties"],
        false
    );
    assert_eq!(
        contract["components"]["schemas"]["PublicJwkSchema"]["additionalProperties"],
        false
    );
    assert!(
        contract["components"]["schemas"]
            .get("IssuerSigningKey")
            .is_none()
    );
    assert_eq!(f.facts().await, (1, 1, 0));
}
