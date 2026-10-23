use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn fixed_get_pages_are_non_authoritative_and_contract_has_no_token_or_default_routes(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    for path in [
        "/oidc/authorize?code=untrusted&state=untrusted",
        "/oidc/authorize.js",
    ] {
        let response = f.app.clone().oneshot(get(path)).await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()["referrer-policy"], "no-referrer");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert!(
            response.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'")
        );
        assert!(!response.headers().contains_key(header::SET_COOKIE));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(!String::from_utf8_lossy(&body).contains("untrusted"));
    }
    assert_eq!(f.count("auth_issuer_authorizations").await, 0);
    assert_eq!(f.count("auth_issuer_subjects").await, 0);
    let api = serde_json::to_value(easy_auth_axum::issuer_consent_openapi()).unwrap();
    for name in [
        "IssuerConsentInput",
        "IssuerConsentDecision",
        "IssuerConsentResume",
    ] {
        assert_eq!(
            api["components"]["schemas"][name]["additionalProperties"],
            false
        );
    }
    assert!(api["paths"].get("/v1/oidc/consent/approve").is_some());
    assert!(api["paths"].get("/oidc/token").is_none());
    let base = crate::support::app(f.pool.clone()).await.0;
    assert_eq!(
        base.oneshot(get("/oidc/authorize")).await.unwrap().status(),
        404
    );
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn consent_composition_requires_exact_https_root_issuer_and_realm(pool: PgPool) {
    let f = Fixture::new(pool).await;
    for (realm, issuer, browser) in [
        (Uuid::new_v4(), ORIGIN, ORIGIN),
        (f.realm, "https://other.example", ORIGIN),
        (f.realm, "https://app.example/path", ORIGIN),
        (f.realm, ORIGIN, "http://127.0.0.1"),
    ] {
        let service = Arc::new(IssuerAuthorization::new(
            IssuerAuthority::new(realm, issuer).unwrap(),
            f.store.clone(),
        ));
        assert!(
            experimental_issuer_consent_router(
                Auth::new(f.realm, f.store.clone(), Arc::new(Mail::default())),
                BrowserConfig::new(browser, true).unwrap(),
                service
            )
            .is_err()
        );
    }
}
