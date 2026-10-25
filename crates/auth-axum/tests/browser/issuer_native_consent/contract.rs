use super::*;
use crate::support::issuer_web::get;
use http_body_util::BodyExt;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn fixed_native_page_is_non_authoritative_and_live_closed_contract_matches_component(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    for path in [
        "/oidc/native/authorize?state=untrusted&redirect_uri=untrusted",
        "/oidc/native/authorize.js",
    ] {
        let response = f.base.app.clone().oneshot(get(path)).await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()["referrer-policy"], "no-referrer");
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
    assert_eq!(f.facts().await, (0, 0, 0, 0));
    let published = serde_json::to_value(easy_auth_axum::issuer_native_consent_openapi()).unwrap();
    let live = read(
        f.base
            .app
            .clone()
            .oneshot(get("/openapi.json"))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(live, published);
    let ids: Vec<_> = live["paths"]
        .as_object()
        .unwrap()
        .values()
        .flat_map(|path| path.as_object().unwrap().values())
        .filter_map(|op| op.get("operationId").and_then(Value::as_str))
        .collect();
    for id in [
        "nativeConsentPrepare",
        "nativeConsentResume",
        "nativeConsentApprove",
        "nativeConsentCancel",
        "nativeConsentAuthorize",
    ] {
        assert_eq!(ids.iter().filter(|value| **value == id).count(), 1);
    }

    for name in [
        "NativeConsentInput",
        "NativeConsentPreview",
        "NativeConsentDecision",
        "NativeConsentResume",
        "NativeConsentReturn",
    ] {
        assert_eq!(
            live["components"]["schemas"][name]["additionalProperties"],
            false
        );
    }
    assert!(
        live["paths"]
            .get("/v1/oidc/native/consent/approve")
            .is_some()
    );
    for absent in [
        "/oidc/token",
        "/oidc/revoke",
        "/.well-known/openid-configuration",
    ] {
        assert!(live["paths"].get(absent).is_none());
    }
    let default = crate::support::app(f.base.pool.clone()).await.0;
    assert_eq!(
        default
            .oneshot(get("/oidc/native/authorize"))
            .await
            .unwrap()
            .status(),
        404
    );
    for (realm, issuer, browser) in [
        (uuid::Uuid::new_v4(), ORIGIN, ORIGIN),
        (f.base.realm, "https://other.example", ORIGIN),
        (f.base.realm, ORIGIN, "http://127.0.0.1"),
    ] {
        let native = Arc::new(IssuerNativeAuthorization::new(
            IssuerAuthority::new(realm, issuer).unwrap(),
            f.base.store.clone(),
        ));
        assert!(
            experimental_issuer_native_consent_router(
                Auth::new(f.base.realm, f.base.store.clone(), f.mail.clone()),
                BrowserConfig::new(browser, true).unwrap(),
                Arc::new(IssuerAuthorization::new(
                    f.policy.authority().clone(),
                    f.base.store.clone()
                )),
                native
            )
            .is_err()
        );
    }
}
