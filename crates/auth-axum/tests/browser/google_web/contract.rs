use super::setup::*;
use axum::{body::Body, http::Request};
use serde_json::Value;
use sqlx::PgPool;
use std::sync::atomic::Ordering;

#[sqlx::test]
async fn google_http_contract_is_explicit_and_generic_and_default_contracts_remain_separate(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
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
        "/../../docs/architecture/openapi-google-web.json"
    )))
    .unwrap();
    assert_eq!(actual, documented);
    for path in [
        "/v1/google/sign-in/start",
        "/v1/google/sign-in/finish",
        "/v1/google/sign-in/cancel",
        "/v1/account/google-delete/start",
        "/v1/account/google-delete/finish",
        "/v1/account/google-delete/cancel",
        "/google/callback",
        "/google/sign-in",
        "/google/account-delete",
    ] {
        assert!(actual["paths"].get(path).is_some());
    }
    for api in [
        easy_auth_axum::openapi(),
        easy_auth_axum::oidc_web_openapi(),
    ] {
        assert!(
            serde_json::to_value(api).unwrap()["paths"]
                .get("/v1/google/sign-in/start")
                .is_none()
        );
    }
    assert!(actual["paths"].get("/v1/oidc/sign-in/start").is_none());
    assert_eq!(f.provider.document_gets.load(Ordering::SeqCst), 0);
}

#[sqlx::test]
async fn google_callback_bridge_uses_unique_purpose_state_and_discards_foreign_details(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let a = f.start(ROOT, "").await;
    for error in ["access_denied", "server_error"] {
        let query = callback(&a, None, Some(error));
        let r = f
            .send(
                Request::builder()
                    .uri(format!("/google/callback?{query}"))
                    .header("cookie", &a.cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(r.status(), 200);
        no_session(&r);
        let html = text(r).await;
        assert!(html.contains("data-flow=\"signin\""));
        assert!(!html.contains("private-provider-detail"));
        assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    }
    let query = callback(&a, Some("private-owned-code"), None);
    let state = a
        .url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    let ambiguous = format!("{}; __Host-auth-google-delete-state={state}", a.cookie);
    for cookie in ["".to_owned(), ambiguous] {
        let r = f
            .send(
                Request::builder()
                    .uri(format!("/google/callback?{query}"))
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(r.status(), 200);
        let html = text(r).await;
        assert!(html.contains("Return not confirmed"));
        assert!(!html.contains("private-owned-code"));
    }
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(
        f.post(ROOT, "cancel", serde_json::json!({}), &a.cookie)
            .await
            .status(),
        204
    );
}
