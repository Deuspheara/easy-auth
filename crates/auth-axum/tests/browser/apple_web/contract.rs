use super::setup::*;
use easy_auth_axum::{BrowserConfig, experimental_apple_web_router};
use sqlx::PgPool;

#[sqlx::test]
async fn apple_web_composition_rejects_native_registration_even_with_plain_nonce(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    for nonce in [AppleNonceEncoding::Plain, AppleNonceEncoding::Sha256Hex] {
        let (provider, signer) = Provider::new(now as u64);
        let exchange = Arc::new(
            AppleCodeExchange::new(
                f.policy.configuration().clone(),
                f.store.clone(),
                f.store.clone(),
                signer,
                AppleClientType::Native(nonce),
                provider.clone(),
                provider,
            )
            .unwrap(),
        );
        assert!(
            easy_auth_axum::AppleWebServices::new(
                f.policy.clone(),
                Arc::new(OAuthTransactions::new(
                    f.policy.configuration().clone(),
                    f.store.clone()
                )),
                exchange,
                Arc::new(OidcSignIn::new(f.store.clone()))
            )
            .is_err()
        );
    }
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
}

#[sqlx::test]
async fn apple_http_contract_requires_explicit_composition_and_exact_https_return(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let other = Fixture::with_origin(pool, "https://other.example").await;
    for browser in [
        BrowserConfig::new("http://localhost:12345", true).unwrap(),
        BrowserConfig::new("https://other.example", false).unwrap(),
    ] {
        assert!(
            experimental_apple_web_router(f.auth.clone(), browser, f.services.clone()).is_err()
        );
    }
    assert!(
        experimental_apple_web_router(
            other.auth.clone(),
            BrowserConfig::new(ORIGIN, false).unwrap(),
            f.services.clone()
        )
        .is_err()
    );
    let actual = body_json(
        f.send(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await,
    )
    .await;
    let documented: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/architecture/openapi-apple-web.json"
    )))
    .unwrap();
    assert_eq!(actual, documented);
    for path in [
        "/v1/apple/sign-in/start",
        "/v1/apple/sign-in/finish",
        "/v1/apple/sign-in/cancel",
        "/apple/callback",
        "/apple/sign-in",
    ] {
        assert!(actual["paths"].get(path).is_some());
    }
    assert!(
        serde_json::to_value(easy_auth_axum::openapi()).unwrap()["paths"]
            .get("/apple/callback")
            .is_none()
    );
    assert!(actual["paths"].get("/v1/google/sign-in/start").is_none());
    let r = f
        .send(
            Request::builder()
                .uri("/apple/sign-in")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(r.status(), 200);
    no_session(&r);
    assert!(r.headers().contains_key("strict-transport-security"));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
}
