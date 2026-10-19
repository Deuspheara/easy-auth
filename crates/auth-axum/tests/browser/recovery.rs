use crate::support::*;
use auth_core::{Auth, PasswordService};
use auth_postgres::Postgres;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use easy_auth_axum::BrowserConfig;
use http_body_util::BodyExt;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

#[sqlx::test]
async fn recovery_http_proofs_sessions_and_retryable_notification(pool: PgPool) {
    let store = Postgres::new(pool.clone());
    store.migrate().await.unwrap();
    let realm = Uuid::new_v4();
    store.ensure_realm(realm).await.unwrap();
    let mail = Arc::new(Mail::default());
    let auth = Auth::new(realm, Arc::new(store), mail.clone()).with_passwords(Arc::new(
        PasswordService::new("a compromised example password").unwrap(),
    ));
    let app = easy_auth_axum::router(
        auth.clone(),
        BrowserConfig::new("https://app.example", false).unwrap(),
    );
    let initial = sign_in(&app, &mail, "alice@example.com").await;
    let old = "old synthetic password phrase";
    let new = "new synthetic password phrase";
    let enrolled = app
        .clone()
        .oneshot(post(
            "/v1/password/enroll",
            &serde_json::json!({"password":old}).to_string(),
            Some(&initial),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(enrolled.status(), StatusCode::NO_CONTENT);
    let previous = cookie(&enrolled, "__Host-auth-session=");
    sign_in(&app, &mail, "email-only@example.com").await;
    let mut responses = Vec::new();
    let mut binding = String::new();
    for email in [
        "alice@example.com",
        "unknown@example.com",
        "email-only@example.com",
    ] {
        let response = app
            .clone()
            .oneshot(post(
                "/v1/password/reset/start",
                &serde_json::json!({"email":email}).to_string(),
                None,
                Some("https://app.example"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let current = cookie(&response, "__Host-auth-reset=");
        assert!(
            response.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .contains("Secure")
        );
        if binding.is_empty() {
            binding = current;
        }
        responses.push(response.into_body().collect().await.unwrap().to_bytes());
    }
    assert_eq!(responses[0], responses[1]);
    assert_eq!(responses[0], responses[2]);
    assert_eq!(
        mail.resets.lock().unwrap().len(),
        3,
        "same mail path, independent of account status"
    );
    let token = mail.resets.lock().unwrap()[0].clone();
    let body = serde_json::json!({"token":token,"password":new}).to_string();
    for (cookie, origin, status) in [
        (None, Some("https://app.example"), StatusCode::UNAUTHORIZED),
        (Some(binding.as_str()), None, StatusCode::FORBIDDEN),
    ] {
        assert_eq!(
            app.clone()
                .oneshot(post("/v1/password/reset/finish", &body, cookie, origin))
                .await
                .unwrap()
                .status(),
            status
        );
    }
    let invalid =
        serde_json::json!({"token":token,"password":"a compromised example password"}).to_string();
    assert_eq!(
        app.clone()
            .oneshot(post(
                "/v1/password/reset/finish",
                &invalid,
                Some(&binding),
                Some("https://app.example")
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    *mail.fail_notices.lock().unwrap() = true;
    let completed = app
        .clone()
        .oneshot(post(
            "/v1/password/reset/finish",
            &body,
            Some(&binding),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(completed.status(), StatusCode::NO_CONTENT);
    assert!(
        completed
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .all(|h| h.to_str().unwrap().contains("Max-Age=0"))
    );
    assert_eq!(
        app.clone()
            .oneshot(post(
                "/v1/password/reset/finish",
                &body,
                Some(&binding),
                Some("https://app.example")
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/session")
                    .header(header::COOKIE, &previous)
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    for (password, expected) in [
        (old, StatusCode::UNAUTHORIZED),
        (new, StatusCode::NO_CONTENT),
    ] {
        let response = app
            .clone()
            .oneshot(post(
                "/v1/password/login",
                &serde_json::json!({"email":"alice@example.com","password":password}).to_string(),
                None,
                Some("https://app.example"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    assert!(auth.deliver_security_notice().await.is_err());
    sqlx::query("UPDATE auth_security_notifications SET next_attempt_at=clock_timestamp()-interval '1 second'").execute(&pool).await.unwrap();
    *mail.fail_notices.lock().unwrap() = false;
    assert!(auth.deliver_security_notice().await.unwrap());
    assert!(!auth.deliver_security_notice().await.unwrap());
    assert_eq!(*mail.notices.lock().unwrap(), 1);
    assert_eq!(
        app.oneshot(
            Request::builder()
                .uri("/v1/password/reset/finish?token=ignored")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap()
        .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
}
