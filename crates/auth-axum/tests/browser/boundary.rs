use crate::support::*;
use auth_core::Secret;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use sqlx::PgPool;
use tower::ServiceExt;

#[sqlx::test]
async fn reject_origin_body_and_cookie_attacks(pool: PgPool) {
    let (app, mail) = app(pool).await;
    for origin in [
        None,
        Some("null"),
        Some("https://evil.example"),
        Some("https://app.example.evil"),
    ] {
        assert_eq!(
            app.clone()
                .oneshot(post(
                    "/v1/email/start",
                    r#"{"email":"a@example.com"}"#,
                    None,
                    origin
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    assert!(mail.0.lock().unwrap().is_empty());
    let big = serde_json::json!({"email":"a".repeat(9000)}).to_string();
    assert_eq!(
        app.clone()
            .oneshot(post(
                "/v1/email/start",
                &big,
                None,
                Some("https://app.example")
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let token = Secret::generate().unwrap();
    let cookie = format!(
        "__Host-auth-session={}; __Host-auth-session={}",
        token.expose(),
        token.expose()
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/session")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        app.oneshot(
            Request::builder()
                .uri("/v1/email/finish?token=ignored")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap()
        .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
}
