use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn reference_recovery_pages_are_opt_in_non_mutating_and_keep_shared_browser_headers(
    pool: PgPool,
) {
    let r = Recovery::new(pool, true).await;
    let before = r.snapshot().await;
    for path in [
        "/passkey-recovery",
        "/passkey-recovery/setup",
        "/passkey-recovery/shared.js",
        "/passkey-recovery/setup.js",
        "/passkey-recovery/recover.js",
    ] {
        for app in [
            easy_auth_axum::router(r.f.auth.clone(), BrowserConfig::new(ORIGIN, false).unwrap()),
            r.f.app.clone(),
        ] {
            let response = app
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
        let response = r
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("{path}?code=untrusted-proof-marker#ignored"))
                    .header(header::COOKIE, r.f.cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()["referrer-policy"], "no-referrer");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        let csp = response.headers()["content-security-policy"]
            .to_str()
            .unwrap();
        assert!(csp.contains("script-src 'self'") && csp.contains("frame-ancestors 'none'"));
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        let content = response.headers()[header::CONTENT_TYPE].to_str().unwrap();
        assert!(content.starts_with(if path.ends_with(".js") {
            "text/javascript"
        } else {
            "text/html"
        }));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(!String::from_utf8_lossy(&body).contains("untrusted-proof-marker"));
    }
    assert!(
        r.snapshot().await == before,
        "GET pages/assets cannot prepare code, reserve claims or issue/touch sessions"
    );
}
