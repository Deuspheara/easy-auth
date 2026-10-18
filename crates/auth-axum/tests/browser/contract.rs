use crate::support::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;

#[sqlx::test]
async fn published_contract_matches_live_spec_and_rejections_are_redacted(pool: PgPool) {
    let (app, _) = app(pool).await;
    let spec = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(spec.status(), StatusCode::OK);
    let live: serde_json::Value =
        serde_json::from_slice(&spec.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let published: serde_json::Value =
        serde_json::from_str(include_str!("../../../../docs/openapi.json")).unwrap();
    assert_eq!(
        live, published,
        "regenerate docs/openapi.json when changing the contract"
    );
    assert_eq!(
        live["paths"]["/v1/email/start"]["post"]["responses"]["202"]["description"],
        "Generic response; sets HttpOnly browser binding"
    );
    let malformed = app
        .oneshot(post(
            "/v1/email/finish",
            r#"{"token":123,"secret":"must-not-echo"}"#,
            None,
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    let body = malformed.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        serde_json::json!({"code":"invalid_body"})
    );
}
