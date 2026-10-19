use crate::support::*;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;

#[sqlx::test]
async fn browser_email_session_logout_end_to_end(pool: PgPool) {
    let (app, mail) = app(pool).await;
    let start = app
        .clone()
        .oneshot(post(
            "/v1/email/start",
            r#"{"email":"alice@example.com"}"#,
            None,
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(start.status(), StatusCode::ACCEPTED);
    let browser = cookie(&start, "__Host-auth-browser=");
    assert!(
        start.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Secure")
    );
    let token = mail.sign_ins.lock().unwrap()[0].clone();
    let body = serde_json::json!({"token":token}).to_string();
    let invalid = app
        .clone()
        .oneshot(post(
            "/v1/email/finish",
            &body,
            None,
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
    let finished = app
        .clone()
        .oneshot(post(
            "/v1/email/finish",
            &body,
            Some(&browser),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(finished.status(), StatusCode::NO_CONTENT);
    let session = cookie(&finished, "__Host-auth-session=");
    let replay = app
        .clone()
        .oneshot(post(
            "/v1/email/finish",
            &body,
            Some(&browser),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    let request = || {
        Request::builder()
            .uri("/v1/session")
            .header(header::COOKIE, &session)
            .body(Body::empty())
            .unwrap()
    };
    let protected = app.clone().oneshot(request()).await.unwrap();
    assert_eq!(protected.status(), StatusCode::OK);
    assert_eq!(protected.headers()[header::CACHE_CONTROL], "no-store");
    let user: serde_json::Value =
        serde_json::from_slice(&protected.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(user["email"], "alice@example.com");
    assert!(user.get("token").is_none());
    let logout = app
        .clone()
        .oneshot(post(
            "/v1/logout",
            "{}",
            Some(&session),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(logout.status(), StatusCode::NO_CONTENT);
    assert!(
        logout.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    assert_eq!(
        app.oneshot(request()).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}
