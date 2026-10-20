use super::setup::*;
use axum::{body::Body, http::Request};
use serde_json::Value;
use sqlx::PgPool;

#[sqlx::test]
async fn served_contract_matches_generated_snapshot_and_default_stays_separate(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let r = f
        .send(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(r.status(), 200);
    let actual = body(r).await;
    let documented: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/architecture/openapi-oidc-web.json"
    )))
    .unwrap();
    assert_eq!(actual, documented);
    let default = serde_json::to_value(easy_auth_axum::openapi()).unwrap();
    assert!(default["paths"].get("/v1/oidc/sign-in/start").is_none());
    for path in [
        "/v1/oidc/sign-in/start",
        "/v1/oidc/sign-in/finish",
        "/v1/oidc/sign-in/cancel",
        "/oidc/callback",
        "/oidc/sign-in",
        "/v1/account/provider-delete/finish",
    ] {
        assert!(
            actual["paths"].get(path).is_some(),
            "named route has a concrete contract"
        );
    }
}
